// Utility functions
package utils

import (
	"encoding/json"
	"fmt"
	"log"
	"os"
	"path/filepath"
)

// EnsureDirectoryExists creates a directory if it doesn't exist
func EnsureDirectoryExists(path string) error {
	dir := filepath.Dir(path)
	if _, err := os.Stat(dir); os.IsNotExist(err) {
		return os.MkdirAll(dir, 0755)
	}
	return nil
}

// PrettyPrint outputs a JSON-formatted string of the provided object for debugging
func PrettyPrint(v interface{}) string {
	b, err := json.MarshalIndent(v, "", "  ")
	if err != nil {
		return fmt.Sprintf("Error: %v", err)
	}
	return string(b)
}

// LogError logs an error message
func LogError(format string, v ...interface{}) {
	log.Printf("ERROR: "+format, v...)
}

// LogInfo logs an informational message
func LogInfo(format string, v ...interface{}) {
	log.Printf("INFO: "+format, v...)
}
