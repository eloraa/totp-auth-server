package main

import (
	"database/sql"
	"fmt"
	"log"
	"os"

	_ "github.com/jackc/pgx/v5/stdlib"
)

func main() {
	dbURL := os.Getenv("DATABASE_URL")
	if dbURL == "" {
		log.Fatal("DATABASE_URL not set")
	}
	db, err := sql.Open("pgx", dbURL)
	if err != nil {
		log.Fatalf("failed to connect to db: %v", err)
	}
	defer db.Close()

	_, err = db.Exec(`
		CREATE TABLE IF NOT EXISTS auth_service (
			id TEXT PRIMARY KEY,
			user_id TEXT NOT NULL REFERENCES public.user(id) ON DELETE CASCADE,
			name TEXT NOT NULL,
			key TEXT NOT NULL,
			service TEXT,
			created_at TIMESTAMP NOT NULL DEFAULT NOW(),
			updated_at TIMESTAMP NOT NULL DEFAULT NOW()
		);
		ALTER TABLE auth_service ADD COLUMN IF NOT EXISTS service TEXT;
		CREATE INDEX IF NOT EXISTS idx_auth_service_user_id ON auth_service(user_id);
	`)
	if err != nil {
		log.Fatalf("migration failed: %v", err)
	}
	fmt.Println("Migration completed successfully.")
}
