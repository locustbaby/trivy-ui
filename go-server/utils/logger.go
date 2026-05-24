package utils

import (
	"encoding/json"
	"fmt"
	"os"
	"strings"
	"time"
)

type LogLevel string

const (
	LevelDebug   LogLevel = "debug"
	LevelInfo    LogLevel = "info"
	LevelWarning LogLevel = "warning"
	LevelError   LogLevel = "error"
)

var levelOrder = map[LogLevel]int{
	LevelDebug:   0,
	LevelInfo:    1,
	LevelWarning: 2,
	LevelError:   3,
}

var currentLevel LogLevel

func init() {
	raw := strings.ToLower(strings.TrimSpace(os.Getenv("LOG_LEVEL")))
	switch raw {
	case "debug":
		currentLevel = LevelDebug
	case "warning", "warn":
		currentLevel = LevelWarning
	case "error":
		currentLevel = LevelError
	default:
		currentLevel = LevelInfo
	}
}

type LogEntry struct {
	Timestamp string                 `json:"timestamp"`
	Level     LogLevel               `json:"level"`
	Message   string                 `json:"message"`
	Fields    map[string]interface{} `json:"fields,omitempty"`
}

func logJSON(level LogLevel, message string, fields map[string]interface{}) {
	if levelOrder[level] < levelOrder[currentLevel] {
		return
	}
	entry := LogEntry{
		Timestamp: time.Now().Format(time.RFC3339),
		Level:     level,
		Message:   message,
		Fields:    fields,
	}
	data, err := json.Marshal(entry)
	if err != nil {
		errorEntry := LogEntry{
			Timestamp: time.Now().Format(time.RFC3339),
			Level:     LevelError,
			Message:   "Failed to marshal log entry",
			Fields:    map[string]interface{}{"error": err.Error()},
		}
		errorData, _ := json.Marshal(errorEntry)
		fmt.Fprintln(os.Stderr, string(errorData))
		return
	}
	if level == LevelError || level == LevelWarning {
		fmt.Fprintln(os.Stderr, string(data))
	} else {
		fmt.Println(string(data))
	}
}

func LogDebug(message string, fields ...map[string]interface{}) {
	var f map[string]interface{}
	if len(fields) > 0 {
		f = fields[0]
	}
	logJSON(LevelDebug, message, f)
}

func LogInfo(message string, fields ...map[string]interface{}) {
	var f map[string]interface{}
	if len(fields) > 0 {
		f = fields[0]
	}
	logJSON(LevelInfo, message, f)
}

func LogWarning(message string, fields ...map[string]interface{}) {
	var f map[string]interface{}
	if len(fields) > 0 {
		f = fields[0]
	}
	logJSON(LevelWarning, message, f)
}

func LogError(message string, fields ...map[string]interface{}) {
	var f map[string]interface{}
	if len(fields) > 0 {
		f = fields[0]
	}
	logJSON(LevelError, message, f)
}

func LogAccess(clientIP, method, path string, statusCode, size int, duration time.Duration) {
	fields := map[string]interface{}{
		"ip":     clientIP,
		"method": method,
		"path":   path,
		"status": statusCode,
		"size":   size,
		"ms":     duration.Milliseconds(),
	}
	level := LevelInfo
	if statusCode >= 500 {
		level = LevelError
	} else if statusCode >= 400 {
		level = LevelWarning
	}
	logJSON(level, "request", fields)
}
