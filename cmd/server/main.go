package main

import (
	"authinticator/pkg/config"
	"authinticator/pkg/db"
	"authinticator/pkg/server"
	"log"

	"github.com/joho/godotenv"
)

func main() {
	if err := godotenv.Load(); err == nil {
		log.Println("[DEBUG] Loaded .env file")
	} else {
		log.Println("[DEBUG] No .env file found or error loading .env")
	}
	cfg := config.Load()
	dbConn, err := db.Connect(cfg.DatabaseURL)
	if err != nil {
		log.Fatalf("failed to connect to db: %v", err)
	}
	defer dbConn.Close()

	srv := server.NewServer(dbConn, cfg.SessionSecret, cfg.Debug, cfg.CORSOrigins, cfg.CORSMethods, cfg.CORSHeaders, cfg.KeyEncryptSalt)
	log.Printf("Server started on %s", cfg.ListenAddr)
	if err := srv.Start(cfg.ListenAddr); err != nil {
		log.Fatalf("server error: %v", err)
	}
}
