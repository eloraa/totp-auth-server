package handler

import (
	"authinticator/pkg/server"
	"net/http"
)

func Handler(w http.ResponseWriter, r *http.Request) {
	server.GetServer().Engine.ServeHTTP(w, r)
}
