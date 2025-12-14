package utils

import (
	"encoding/json"
	"fmt"
	"os"
	"time"
)

type LogLevel string

const (
	LevelInfo    LogLevel = "info"
	LevelWarning LogLevel = "warning"
	LevelError   LogLevel = "error"
	LevelDebug   LogLevel = "debug"
)

type LogEntry struct {
	Timestamp string                 `json:"timestamp"`
	Level     LogLevel               `json:"level"`
	Message   string                 `json:"message"`
	Fields    map[string]interface{} `json:"fields,omitempty"`
}

func logJSON(level LogLevel, message string, fields map[string]interface{}) {
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
	fmt.Println(string(data))
}

func LogInfo(message string, fields ...map[string]interface{}) {
	var mergedFields map[string]interface{}
	if len(fields) > 0 {
		mergedFields = fields[0]
	}
	logJSON(LevelInfo, message, mergedFields)
}

func LogWarning(message string, fields ...map[string]interface{}) {
	var mergedFields map[string]interface{}
	if len(fields) > 0 {
		mergedFields = fields[0]
	}
	logJSON(LevelWarning, message, mergedFields)
}

func LogError(message string, fields ...map[string]interface{}) {
	var mergedFields map[string]interface{}
	if len(fields) > 0 {
		mergedFields = fields[0]
	}
	logJSON(LevelError, message, mergedFields)
}

func LogDebug(message string, fields ...map[string]interface{}) {
	var mergedFields map[string]interface{}
	if len(fields) > 0 {
		mergedFields = fields[0]
	}
	logJSON(LevelDebug, message, mergedFields)
}

func LogAccess(clientIP, method, path, proto string, statusCode, size int, referer, userAgent string, duration time.Duration) {
	fields := map[string]interface{}{
		"client_ip":   clientIP,
		"method":      method,
		"path":        path,
		"proto":       proto,
		"status_code": statusCode,
		"size":        size,
		"referer":     referer,
		"user_agent":  userAgent,
		"duration_ms": duration.Milliseconds(),
	}
	logJSON(LevelInfo, "access", fields)
}
