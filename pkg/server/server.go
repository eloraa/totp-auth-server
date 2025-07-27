package server

import (
	"database/sql"

	"authinticator/pkg/config"
	"authinticator/pkg/db"
	"sync"

	"github.com/gin-gonic/gin"
)

var (
	srv  *Server
	once sync.Once
)

type Server struct {
	DB             *sql.DB
	Secret         string
	Engine         *gin.Engine
	Debug          bool
	CORSOrigins    []string
	CORSMethods    []string
	CORSHeaders    []string
	KeyEncryptSalt string
}

func NewServer(db *sql.DB, secret string, debug bool, corsOrigins, corsMethods, corsHeaders []string, keyEncryptSalt string) *Server {
	s := &Server{
		DB:             db,
		Secret:         secret,
		Debug:          debug,
		CORSOrigins:    corsOrigins,
		CORSMethods:    corsMethods,
		CORSHeaders:    corsHeaders,
		KeyEncryptSalt: keyEncryptSalt,
	}
	s.Engine = s.setupRouter()
	return s
}

func (s *Server) Start(addr string) error {
	return s.Engine.Run(addr)
}

// GetServer returns a singleton instance of Server, initializing it if necessary.
func GetServer() *Server {
	once.Do(func() {
		cfg := config.Load()
		dbConn, err := db.Connect(cfg.DatabaseURL)
		if err != nil {
			panic(err)
		}
		srv = NewServer(dbConn, cfg.SessionSecret, cfg.Debug, cfg.CORSOrigins, cfg.CORSMethods, cfg.CORSHeaders, cfg.KeyEncryptSalt)
	})
	return srv
}
