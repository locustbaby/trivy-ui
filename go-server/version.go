package main

import (
	"os"
	"strings"
)

// GetVersion reads the version from environment or VERSION file
func GetVersion() string {
	// First check if version is set as an environment variable
	if version := os.Getenv("VERSION"); version != "" {
		return version
	}
	
	// Then check if VERSION file exists in the current directory
	if data, err := os.ReadFile("VERSION"); err == nil {
		return strings.TrimSpace(string(data))
	}
	
	// Then check if VERSION file exists in the parent directory
	if data, err := os.ReadFile("../VERSION"); err == nil {
		return strings.TrimSpace(string(data))
	}
	
	// Then check if VERSION file exists in the go-server directory
	if data, err := os.ReadFile("go-server/VERSION"); err == nil {
		return strings.TrimSpace(string(data))
	}
	
	// Default version if all else fails
	return "0.0.0-dev"
}
