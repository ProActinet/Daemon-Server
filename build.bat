@echo off
echo Building for Linux AMD64 (x86_64)...

set GOOS=linux
set GOARCH=amd64

go build -o ./streams ./main.go
if %ERRORLEVEL% neq 0 (
    echo Build failed for Linux AMD64 (x86_64)
    exit /b %ERRORLEVEL%
)

echo Build successful: ./streamchanges/streams
echo Done!
