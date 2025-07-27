package config

import (
	"log"
	"os"
	"strings"
)

type Config struct {
	DatabaseURL    string
	SessionSecret  string
	ListenAddr     string
	Debug          bool
	CORSOrigins    []string
	CORSMethods    []string
	CORSHeaders    []string
	KeyEncryptSalt string
}

func Load() *Config {
	dbg := getEnv("DEBUG", "false") == "true"
	log.Printf("[DEBUG] DEBUG env variable: %v", dbg)
	return &Config{
		DatabaseURL:    os.Getenv("DATABASE_URL"),
		SessionSecret:  os.Getenv("SESSION_SECRET"),
		ListenAddr:     getEnv("LISTEN_ADDR", ":8080"),
		Debug:          dbg,
		CORSOrigins:    splitEnv("CORS_ORIGINS", "*"),
		CORSMethods:    splitEnv("CORS_METHODS", "GET,POST,PUT,DELETE,OPTIONS"),
		CORSHeaders:    splitEnv("CORS_HEADERS", "Authorization,Content-Type,Origin,Accept"),
		KeyEncryptSalt: os.Getenv("KEY_ENCRYPT_SALT"),
	}
}

func getEnv(key, fallback string) string {
	if v := os.Getenv(key); v != "" {
		return v
	}
	return fallback
}

func splitEnv(key, fallback string) []string {
	v := getEnv(key, fallback)
	parts := strings.Split(v, ",")
	for i := range parts {
		parts[i] = strings.TrimSpace(parts[i])
	}
	return parts
}
