package config

import (
	"os"
	"path/filepath"
	"strconv"
)

var config *Config

type Config struct {
	Host       string
	Port       int
	DataPath   string
	StaticPath string
}

func Get() *Config {
	if config == nil {
		config = &Config{
			Host:       getEnv("HOST", "0.0.0.0"),
			Port:       getEnvInt("PORT", 8080),
			DataPath:   getEnv("DATA_PATH", "."),
			StaticPath: getEnv("STATIC_PATH", "static"),
		}
	}
	return config
}

func getEnv(key, defaultValue string) string {
	if value := os.Getenv(key); value != "" {
		return value
	}
	return defaultValue
}

func getEnvInt(key string, defaultValue int) int {
	if value := os.Getenv(key); value != "" {
		if intValue, err := strconv.Atoi(value); err == nil {
			return intValue
		}
	}
	return defaultValue
}

func KubeConfigPath() string {
	if path := os.Getenv("KUBECONFIG"); path != "" {
		return path
	}
	return filepath.Join(os.Getenv("HOME"), ".kube", "config")
}
