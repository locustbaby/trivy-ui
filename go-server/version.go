package main

import (
	"os"
	"strings"
)

func GetVersion() string {

	if version := os.Getenv("VERSION"); version != "" {
		return version
	}

	if data, err := os.ReadFile("VERSION"); err == nil {
		return strings.TrimSpace(string(data))
	}

	if data, err := os.ReadFile("../VERSION"); err == nil {
		return strings.TrimSpace(string(data))
	}

	if data, err := os.ReadFile("go-server/VERSION"); err == nil {
		return strings.TrimSpace(string(data))
	}

	return "0.0.0-dev"
}
