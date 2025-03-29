package main

import (
	"bytes"
	"encoding/json"
	"errors"
	"fmt"
	envloader "local-server/envLoader"
	"log"
	"net/http"
	"net/url"
	"os"
	"os/exec"
	"sync"
	"time"

	"github.com/gorilla/websocket"
	"github.com/hpcloud/tail"
	"gorm.io/driver/postgres"
	"gorm.io/gorm"
)

const (
	djangoWSUrl = "ws://localhost:8000/ws/daemon-watcher/"
	filePath    = "/var/log/suricata/eve.json"
	emailTo     = "test@gmail.com"
	bufferSize  = 5
	apiKey      = "xkeysib--yV5Tb2X30T5p0Y46"
	brevoAPI    = "https://api.brevo.com/v3/smtp/email"
	licenseFile = "license.json"
	retryDelay  = 5 * time.Second // Reconnect wait duration
)

var (
	buffer        []SuricataLog
	bufferLock    sync.Mutex
	db            *gorm.DB
	messageChan   = make(chan map[string]interface{}, 100) // For WebSocket sender
	stopWebSocket = make(chan bool)
)

type SuricataAlertDetails struct {
	Signature string `json:"signature"`
	Category  string `json:"category"`
	Severity  int    `json:"severity"`
}

type SuricataLog struct {
	Timestamp string               `json:"timestamp"`
	SrcIP     string               `json:"src_ip"`
	SrcPort   int                  `json:"src_port"`
	DestIP    string               `json:"dest_ip"`
	DestPort  int                  `json:"dest_port"`
	Proto     string               `json:"proto"`
	EventType string               `json:"event_type"`
	Alert     SuricataAlertDetails `json:"alert"`
}

type SuricataAlert struct {
	gorm.Model
	Username string          `json:"username" gorm:"uniqueIndex"`
	Email    string          `json:"email"`
	Logs     json.RawMessage `json:"logs" gorm:"type:jsonb"`
}

// ==========================
//        MAIN FUNCTION
// ==========================
func main() {
	initDB()

	// Start the WebSocket sender in a goroutine
	go websocketSender()

	// Start the file watcher (tail logs)
	startFileWatcher(filePath)
}

// ==========================
//      DATABASE SETUP
// ==========================
func initDB() {
	// Load environment variables
	envMap := envloader.EnvLoader()
	// Connect to the database
	dsn := fmt.Sprintf("host=%s user=%s password=%s dbname=%s port=%s sslmode=require",
		envMap["DB_HOST"],
		envMap["DB_USER"],
		envMap["DB_PASSWORD"],
		envMap["DB_NAME"],
		envMap["DB_PORT"],
	)

	var err error
	db, err = gorm.Open(postgres.Open(dsn), &gorm.Config{})
	if err != nil {
		log.Fatalf("Failed to connect to database: %v", err)
	}

	err = db.AutoMigrate(&SuricataAlert{})
	if err != nil {
		log.Fatalf("Failed to migrate database: %v", err)
	}

	log.Println("Database connected and migrated successfully.")
}

// ==========================
//       FILE WATCHER
// ==========================
func startFileWatcher(eveLog string) {
	t, err := tail.TailFile(eveLog, tail.Config{
		Follow: true,
		ReOpen: true,
	})
	if err != nil {
		log.Fatalf("Failed to tail file: %v", err)
	}

	log.Println("Started watching:", eveLog)

	for line := range t.Lines {
		processLogLine(line.Text)
	}
}

func processLogLine(text string) {
	var alert SuricataLog
	if err := json.Unmarshal([]byte(text), &alert); err != nil {
		log.Println("Error parsing JSON:", err)
		return
	}

	// Send raw JSON to WebSocket sender
	var jsonObj map[string]interface{}
	if err := json.Unmarshal([]byte(text), &jsonObj); err == nil {
		messageChan <- jsonObj
	}

	// Add to buffer for DB + Email processing
	addAlertToBuffer(alert)
}

func addAlertToBuffer(alert SuricataLog) {
	bufferLock.Lock()
	defer bufferLock.Unlock()

	buffer = append(buffer, alert)

	if len(buffer) >= bufferSize {
		go func(data []SuricataLog) {
			sendEmail(data)
			saveToDatabase(data)
			clearLogFile(filePath)
			clearBuffer()
		}(buffer)
	}
}

func clearBuffer() {
	buffer = nil
}

// ==========================
//       EMAIL SENDER
// ==========================
func sendEmail(alerts []SuricataLog) {
	if len(alerts) == 0 {
		log.Println("No alerts to send. Skipping email.")
		return
	}

	envMap := envloader.EnvLoader()
	apiKey := envMap["API_KEY"]
	if apiKey == "" {
		log.Println("API key missing. Skipping email.")
		return
	}

	username, emailTo := getSystemInfo()
	if username == "" {
		log.Println("Username missing. Skipping email.")
		return
	}

	emailContent := composeEmailContent(alerts)

	data := map[string]interface{}{
		"sender": map[string]string{
			"name":  "Suricata Monitor",
			"email": "marsal.ded@200630.xyz",
		},
		"to": []map[string]string{
			{"email": emailTo, "name": username},
		},
		"subject":     "Suricata Alert Summary",
		"htmlContent": emailContent,
	}

	jsonData, _ := json.Marshal(data)

	req, err := http.NewRequest("POST", brevoAPI, bytes.NewBuffer(jsonData))
	if err != nil {
		log.Println("Error creating email request:", err)
		return
	}

	req.Header.Set("accept", "application/json")
	req.Header.Set("api-key", apiKey)
	req.Header.Set("content-type", "application/json")

	client := &http.Client{}
	resp, err := client.Do(req)
	if err != nil {
		log.Println("Error sending email:", err)
		return
	}
	defer resp.Body.Close()

	log.Println("Email sent successfully! Status:", resp.Status)
}

func composeEmailContent(alerts []SuricataLog) string {
	content := "<h3>Suricata Alerts</h3>"

	for _, alert := range alerts {
		content += fmt.Sprintf(`
			<p><b>Timestamp:</b> %s</p>
			<p><b>Source IP:</b> %s</p>
			<p><b>Destination IP:</b> %s</p>
			<p><b>Protocol:</b> %s</p>
			<p><b>Signature:</b> %s</p>
			<p><b>Category:</b> %s</p>
			<p><b>Severity:</b> %d</p>
			<hr>
		`, alert.Timestamp, alert.SrcIP, alert.DestIP, alert.Proto, alert.Alert.Signature, alert.Alert.Category, alert.Alert.Severity)
	}

	return content
}

// ==========================
//     DATABASE UPDATER
// ==========================
func saveToDatabase(alerts []SuricataLog) {
	if len(alerts) == 0 {
		return
	}

	username, email := getSystemInfo()

	var existingRecord SuricataAlert
	result := db.Where("username = ?", username).First(&existingRecord)

	alertsJSON, err := json.Marshal(alerts)
	if err != nil {
		log.Println("Error serializing alerts JSON:", err)
		return
	}

	if result.Error != nil {
		if errors.Is(result.Error, gorm.ErrRecordNotFound) {
			newRecord := SuricataAlert{
				Username: username,
				Email:    email,
				Logs:     alertsJSON,
			}

			if err := db.Create(&newRecord).Error; err != nil {
				log.Println("Error creating new record:", err)
			} else {
				log.Println("New record added for user:", username)
			}
		} else {
			log.Println("Error querying database:", result.Error)
		}
		return
	}

	var existingLogs []SuricataLog
	_ = json.Unmarshal(existingRecord.Logs, &existingLogs)
	existingLogs = append(existingLogs, alerts...)

	existingRecord.Logs, _ = json.Marshal(existingLogs)

	if err := db.Save(&existingRecord).Error; err != nil {
		log.Println("Error updating user logs:", err)
	} else {
		log.Println("User logs updated successfully for:", username)
	}
}

// ==========================
//      SYSTEM UTILITIES
// ==========================
func getSystemInfo() (string, string) {
	data, err := os.ReadFile(licenseFile)
	if err != nil {
		log.Printf("Error reading license file: %v", err)
		return "", ""
	}

	var licenseInfo struct {
		Name    string `json:"username"`
		Email   string `json:"email"`
		License string `json:"license"`
	}

	if err := json.Unmarshal(data, &licenseInfo); err != nil {
		log.Printf("Error parsing license file: %v", err)
		return "", ""
	}

	return licenseInfo.Name, licenseInfo.Email
}

func clearLogFile(filePath string) {
	cmd := exec.Command("sudo", "sh", "-c", fmt.Sprintf(`truncate -s 0 %s`, filePath))
	if err := cmd.Run(); err != nil {
		log.Println("Error clearing log file:", err)
	} else {
		log.Println("Log file cleared:", filePath)
	}
}

// ==========================
//     WEBSOCKET HANDLER
// ==========================
func websocketSender() {
    for {
        conn, err := connectWebSocket()
        if err != nil {
            log.Printf("WebSocket connection failed: %v. Retrying in %v...", err, retryDelay)
            time.Sleep(retryDelay)
            continue
        }

        // Set up ping/pong handlers right after connecting.
        conn.SetReadDeadline(time.Now().Add(60 * time.Second))
        conn.SetPongHandler(func(appData string) error {
            conn.SetReadDeadline(time.Now().Add(60 * time.Second))
            return nil
        })

        log.Println("WebSocket connected to Django server")

        // Create a ticker to send ping messages periodically.
        pingTicker := time.NewTicker(30 * time.Second)
        // Use a done channel to signal the end of the ping goroutine.
        done := make(chan struct{})

        // Goroutine to send periodic pings.
        go func() {
            for {
                select {
                case <-pingTicker.C:
                    // Send a ping control message.
                    if err := conn.WriteControl(websocket.PingMessage, []byte{}, time.Now().Add(time.Second)); err != nil {
                        log.Printf("Ping error: %v", err)
                        return
                    }
                case <-done:
                    return
                }
            }
        }()

        // Main loop to send messages from the channel.
        for {
            select {
            case msg := <-messageChan:
                err = conn.WriteJSON(msg)
                if err != nil {
                    log.Printf("WebSocket send error: %v", err)
                    conn.Close()
                    close(done)
                    break
                }
                log.Println("Sent message to Django:", msg)

           	case <-stopWebSocket:
                conn.Close()
                close(done)
                log.Println("WebSocket stopped")
                return
            }
            if err != nil {
                break // Exit the loop to reconnect
            }
        }

        conn.Close()
        pingTicker.Stop()
        log.Println("WebSocket disconnected, retrying...")
        time.Sleep(retryDelay)
    }
}

func connectWebSocket() (*websocket.Conn, error) {
	log.Println("Connecting to Django WebSocket at", djangoWSUrl)
	username, email := getSystemInfo()
	if username == "" || email == "" {
		log.Println("Username or email missing. Skipping WebSocket connection.")
		return nil, errors.New("username missing")
	}

	u, err := url.Parse(djangoWSUrl)
	if err != nil {
		return nil, err
	}

	q := u.Query()
	q.Set("username", username)
	q.Set("email", email)
	u.RawQuery = q.Encode()

	log.Println("Connecting to:", u.String())

	conn, _, err := websocket.DefaultDialer.Dial(u.String(), nil)
	return conn, err
}
