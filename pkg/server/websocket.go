package server

import (
	"authinticator/pkg/models"
	"log"
	"net/http"
	"time"

	"encoding/json"

	"github.com/gin-gonic/gin"
	"github.com/gorilla/websocket"
	"github.com/pquerna/otp/totp"
)

var wsUpgrader = websocket.Upgrader{
	CheckOrigin: func(r *http.Request) bool { return true },
}

// WebSocketHub manages notification for code updates
var wsHub = struct {
	chans map[string]chan struct{}
}{chans: make(map[string]chan struct{})}

func notifyWebSocket(userID string) {
	if ch, ok := wsHub.chans[userID]; ok {
		select {
		case ch <- struct{}{}:
		default:
		}
	}
}

func (s *Server) handleWebsocket(c *gin.Context) {
	if s.Debug {
		log.Printf("[DEBUG] WebSocket connection attempt from %s", c.ClientIP())
	}
	conn, err := wsUpgrader.Upgrade(c.Writer, c.Request, nil)
	if err != nil {
		c.JSON(http.StatusInternalServerError, gin.H{"error": "WebSocket upgrade failed"})
		if s.Debug {
			log.Printf("[DEBUG] WebSocket upgrade failed for %s: %v", c.ClientIP(), err)
		}
		return
	}
	defer conn.Close()
	if s.Debug {
		log.Printf("[DEBUG] WebSocket connection established with %s", c.ClientIP())
	}
	userID := c.GetString("user_id")
	ch := make(chan struct{}, 1)
	wsHub.chans[userID] = ch
	defer delete(wsHub.chans, userID)

	lastCodes := make(map[string]string) // id -> last sent code
	paused := false
	for {
		// Non-blocking check for control messages
		conn.SetReadDeadline(time.Now().Add(100 * time.Millisecond))
		_, msg, err := conn.ReadMessage()
		if err == nil && len(msg) > 0 {
			if s.Debug {
				log.Printf("[DEBUG] Received WS message from %s: %s", c.ClientIP(), string(msg))
			}
			var ctrl struct {
				Action string `json:"action"`
			}
			_ = json.Unmarshal(msg, &ctrl)
			if ctrl.Action == "pause" {
				paused = true
				if s.Debug {
					log.Printf("[DEBUG] Paused WebSocket for %s", c.ClientIP())
				}
				continue
			} else if ctrl.Action == "resume" {
				paused = false
				if s.Debug {
					log.Printf("[DEBUG] Resumed WebSocket for %s", c.ClientIP())
				}
			}
		}
		conn.SetReadDeadline(time.Time{})

		if paused {
			// While paused, block until a resume message is received
			for paused {
				conn.SetReadDeadline(time.Now().Add(10 * time.Second))
				_, msg, err := conn.ReadMessage()
				if err == nil && len(msg) > 0 {
					if s.Debug {
						log.Printf("[DEBUG] Received WS message (paused) from %s: %s", c.ClientIP(), string(msg))
					}
					var ctrl struct {
						Action string `json:"action"`
					}
					_ = json.Unmarshal(msg, &ctrl)
					if ctrl.Action == "resume" {
						paused = false
						if s.Debug {
							log.Printf("[DEBUG] Resumed WebSocket for %s (from paused)", c.ClientIP())
						}
						break
					}
				}
			}
			continue
		}

		rows, err := s.DB.QueryContext(c.Request.Context(), "SELECT id, user_id, name, key, created_at, updated_at FROM auth_service WHERE user_id = $1", userID)
		if err != nil {
			if s.Debug {
				log.Printf("[DEBUG] Failed to query auth_service for ws: %v", err)
			}
			conn.WriteJSON([]map[string]string{{"error": "Failed to fetch services"}})
			return
		}
		var changed []map[string]interface{}
		now := time.Now()
		expiresIn := 30 - (now.Unix() % 30)
		expiresAt := now.Add(time.Duration(expiresIn) * time.Second).UTC().Format(time.RFC3339)
		for rows.Next() {
			var svc models.AuthService
			if err := rows.Scan(&svc.ID, &svc.UserID, &svc.Name, &svc.Key, &svc.CreatedAt, &svc.UpdatedAt); err != nil {
				if s.Debug {
					log.Printf("[DEBUG] Failed to scan auth_service for ws: %v", err)
				}
				continue
			}
			code, err := totp.GenerateCode(svc.Key, now)
			if err != nil {
				code = "error"
				if s.Debug {
					log.Printf("[DEBUG] Error generating TOTP for %s: %v", svc.Name, err)
				}
			}
			if lastCodes[svc.ID] != code {
				changed = append(changed, map[string]interface{}{
					"id":         svc.ID,
					"name":       svc.Name,
					"code":       code,
					"expires_at": expiresAt,
				})
				lastCodes[svc.ID] = code
			}
		}
		rows.Close()
		if len(changed) > 0 {
			if err := conn.WriteJSON(changed); err != nil {
				if s.Debug {
					log.Printf("[DEBUG] WebSocket write error to %s: %v", c.ClientIP(), err)
				}
				return
			}
		}
		// Wait for next code change or notification
		now = time.Now()
		sleep := time.Until(now.Truncate(30 * time.Second).Add(30 * time.Second))
		if sleep < 100*time.Millisecond {
			sleep = 100 * time.Millisecond
		}
		select {
		case <-ch:
			// trigger immediate update
		case <-time.After(sleep):
		}
	}
}
