package envloader

import (
	_ "embed"
	"fmt"
	"log"
	"strings"
)

//go:embed .env
var envFile string

func loadEnv() map[string]string {
	envVars := envFile
	fmt.Println("Loading environment variables from .env file...")
	lines := strings.Split(envVars, "\n")
	envMap := make(map[string]string)
	for _, line := range lines {
		line = strings.TrimSpace(line)
		if len(line) == 0 || strings.HasPrefix(line, "#") {
			continue
		}
		parts := strings.SplitN(line, "=", 2)
		if len(parts) != 2 {
			log.Printf("Ignoring malformed env line: %s", line)
			continue
		}
		key := strings.TrimSpace(parts[0])
		value := strings.TrimSpace(parts[1])
		envMap[key] = value
	}
	return envMap
	// return envVars
}

func EnvLoader() map[string]string {
	log.Println("Loading environment variables...")
	envVars := loadEnv()
	return envVars
	// You can now use envVars which contains all environment variables.
	// For example: log.Println(envVars)
}