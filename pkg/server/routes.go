package server

import (
	"authinticator/pkg/models"
	"authinticator/pkg/utils"
	"context"
	"fmt"
	"log"
	"net/http"
	"strings"
	"time"

	"github.com/gin-contrib/cors"
	"github.com/gin-gonic/gin"
	"github.com/google/uuid"
	"github.com/pquerna/otp/totp"
)

type contextKey string

const sessionTokenKey contextKey = "session_token"

func (s *Server) setupRouter() *gin.Engine {
	if s.Debug {
		gin.SetMode(gin.DebugMode)
	} else {
		gin.SetMode(gin.ReleaseMode)
	}
	engine := gin.New()
	engine.Use(gin.Logger(), gin.Recovery())

	engine.Use(cors.New(cors.Config{
		AllowOrigins:     s.CORSOrigins,
		AllowMethods:     s.CORSMethods,
		AllowHeaders:     s.CORSHeaders,
		AllowCredentials: true,
	}))

	engine.StaticFile("/favicon.ico", "./public/favicon.ico")
	engine.Static("/static", "./public")

	// Custom 404 and 405 handlers
	engine.NoRoute(func(c *gin.Context) {
		c.JSON(http.StatusNotFound, gin.H{"error": "Not found", "path": c.Request.URL.Path})
	})
	engine.NoMethod(func(c *gin.Context) {
		c.JSON(http.StatusMethodNotAllowed, gin.H{"error": "Method not allowed", "path": c.Request.URL.Path})
	})

	engine.GET("/health", s.handleHealth)
	engine.GET("/login", s.handleLogin)
	engine.GET("/list", s.withSession(s.handleList))
	engine.POST("/add", s.withSession(s.handleAdd))
	engine.PUT("/edit", s.withSession(s.handleEdit))
	engine.GET("/ws", s.withSession(s.handleWebsocket))
	engine.GET("/code", s.withSession(s.handleCode))
	engine.DELETE("/delete", s.withSession(s.handleDelete))
	engine.POST("/export", s.withSession(s.handleExport))

	return engine
}

func (s *Server) handleHealth(c *gin.Context) {
	if s.Debug {
		log.Printf("[DEBUG] Health check requested from %s", c.ClientIP())
	}
	c.JSON(http.StatusOK, gin.H{"status": "ok"})
}

func (s *Server) handleLogin(c *gin.Context) {
	tokenParam := c.Query("token")
	if tokenParam == "" {
		if s.Debug {
			log.Printf("[DEBUG] Missing token parameter from %s", c.ClientIP())
		}
		c.JSON(http.StatusBadRequest, gin.H{"error": "Missing token parameter"})
		return
	}

	if s.Debug {
		log.Printf("[DEBUG] Login attempt with token: %s", tokenParam)
	}

	// Extract the raw token from the query string to preserve URL encoding
	rawToken := extractTokenFromRawQuery(c.Request.URL.RawQuery, "token")
	if rawToken == "" {
		rawToken = tokenParam // fallback to decoded version
	}

	if s.Debug {
		log.Printf("[DEBUG] Raw token: %s", rawToken)
	}

	// Don't decode the token here - VerifySignedCookie handles URL decoding internally
	verifiedToken, valid := utils.VerifySignedCookie(rawToken, s.Secret)
	if s.Debug {
		log.Printf("[DEBUG] VerifySignedCookie result: valid=%v, verifiedToken=%s", valid, verifiedToken)
	}
	if !valid {
		if s.Debug {
			log.Printf("[DEBUG] Invalid signed cookie from %s", c.ClientIP())
		}
		c.JSON(http.StatusUnauthorized, gin.H{"error": "Invalid token signature"})
		return
	}

	userID, err := utils.GetUserIDFromToken(c.Request.Context(), s.DB, verifiedToken)
	if err != nil {
		if s.Debug {
			log.Printf("[DEBUG] Invalid token from %s: %v", c.ClientIP(), err)
		}
		c.JSON(http.StatusUnauthorized, gin.H{"error": "Invalid token"})
		return
	}

	c.Header("Set-Cookie", fmt.Sprintf("better-auth.session_token=%s; Max-Age=86400; Path=/; HttpOnly; SameSite=None; Secure", verifiedToken))

	if s.Debug {
		log.Printf("[DEBUG] Login successful for user %s from %s", userID, c.ClientIP())
	}

	c.JSON(http.StatusOK, gin.H{"message": "Login successful"})
}

func (s *Server) handleList(c *gin.Context) {
	userID := c.GetString("user_id")
	includeKey := c.Query("include_key") == "true"
	rows, err := s.DB.QueryContext(c.Request.Context(), "SELECT id, user_id, name, key, created_at, updated_at FROM auth_service WHERE user_id = $1", userID)
	if err != nil {
		if s.Debug {
			log.Printf("[DEBUG] Failed to query auth_service: %v", err)
		}
		c.JSON(500, gin.H{"error": "Failed to list services"})
		return
	}
	defer rows.Close()
	var services []map[string]interface{}
	for rows.Next() {
		var svc models.AuthService
		if err := rows.Scan(&svc.ID, &svc.UserID, &svc.Name, &svc.Key, &svc.CreatedAt, &svc.UpdatedAt); err != nil {
			if s.Debug {
				log.Printf("[DEBUG] Failed to scan auth_service: %v", err)
			}
			continue
		}
		item := map[string]interface{}{
			"id":         svc.ID,
			"user_id":    svc.UserID,
			"name":       svc.Name,
			"created_at": svc.CreatedAt,
			"updated_at": svc.UpdatedAt,
		}
		if includeKey {
			encrypted, err := utils.EncryptKey(svc.Key, s.KeyEncryptSalt)
			if err == nil {
				item["key"] = encrypted
			} else if s.Debug {
				log.Printf("[DEBUG] Failed to encrypt key for %s: %v", svc.Name, err)
			}
		}
		services = append(services, item)
	}
	c.JSON(200, services)
}

func (s *Server) handleAdd(c *gin.Context) {
	userID := c.GetString("user_id")
	var req models.AuthService
	if err := c.ShouldBindJSON(&req); err != nil {
		if s.Debug {
			log.Printf("[DEBUG] Invalid request body: %v", err)
		}
		c.JSON(400, gin.H{"error": "Invalid request body"})
		return
	}
	if req.Name == "" && req.Key == "" {
		if s.Debug {
			log.Printf("[DEBUG] Missing name or key: %+v", req)
		}
		c.JSON(400, gin.H{"error": "Missing name or key"})
		return
	}
	if strings.HasPrefix(req.Key, "otpauth-migration://") {
		pairs, err := utils.ExtractSecretsFromMigrationURL(req.Key)
		services, _ := utils.ExtractServiceNamesFromMigrationURL(req.Key)
		if err != nil || len(pairs) == 0 {
			c.JSON(400, gin.H{"error": "Invalid otpauth-migration URL"})
			return
		}
		var added []string
		for i, pair := range pairs {
			name, secret := pair[0], pair[1]
			service := ""
			if i < len(services) {
				service = services[i]
			}
			if !utils.ValidateTOTPSecret(secret) {
				continue
			}
			id := uuid.NewString()
			_, err := s.DB.ExecContext(c.Request.Context(),
				"INSERT INTO auth_service (id, user_id, name, key, service, created_at, updated_at) VALUES ($1, $2, $3, $4, $5, NOW(), NOW())",
				id, userID, name, secret, service,
			)
			if err == nil {
				added = append(added, name)
			}
		}
		if len(added) == 0 {
			c.JSON(400, gin.H{"error": "No valid secrets found in migration URL"})
			return
		}
		notifyWebSocket(userID)
		c.JSON(201, gin.H{"message": "Added", "services": added})
		return
	}
	secret := utils.ExtractTOTPSecret(req.Key)
	service := utils.ExtractServiceNameFromKey(req.Key)
	if !utils.ValidateTOTPSecret(secret) {
		if s.Debug {
			log.Printf("[DEBUG] Invalid TOTP secret for %s: %s", req.Name, req.Key)
		}
		c.JSON(400, gin.H{"error": "Invalid TOTP secret or QR code data"})
		return
	}

	name := req.Name
	if name == "" {
		name = service
	}

	id := uuid.NewString()
	_, err := s.DB.ExecContext(c.Request.Context(),
		"INSERT INTO auth_service (id, user_id, name, key, service, created_at, updated_at) VALUES ($1, $2, $3, $4, $5, NOW(), NOW())",
		id, userID, name, secret, service,
	)
	if err != nil {
		if s.Debug {
			log.Printf("[DEBUG] Failed to insert auth_service: %v", err)
		}
		c.JSON(500, gin.H{"error": "Failed to add service"})
		return
	}
	notifyWebSocket(userID)
	if s.Debug {
		log.Printf("[DEBUG] Added service: %+v for user %s", req, userID)
	}
	c.JSON(201, gin.H{"message": "Added"})
}

func (s *Server) handleEdit(c *gin.Context) {
	userID := c.GetString("user_id")
	var req struct {
		ID   string `json:"id" binding:"required"`
		Name string `json:"name" binding:"required"`
	}
	if err := c.ShouldBindJSON(&req); err != nil {
		if s.Debug {
			log.Printf("[DEBUG] Invalid request body for edit: %v", err)
		}
		c.JSON(400, gin.H{"error": "Invalid request body"})
		return
	}

	if req.Name == "" {
		c.JSON(400, gin.H{"error": "Name cannot be empty"})
		return
	}

	res, err := s.DB.ExecContext(c.Request.Context(),
		"UPDATE auth_service SET name = $1, updated_at = NOW() WHERE id = $2 AND user_id = $3",
		req.Name, req.ID, userID)
	if err != nil {
		if s.Debug {
			log.Printf("[DEBUG] Failed to update auth_service: %v", err)
		}
		c.JSON(500, gin.H{"error": "Failed to update service"})
		return
	}

	n, _ := res.RowsAffected()
	if n == 0 {
		c.JSON(404, gin.H{"error": "Service not found or not owned by user"})
		return
	}

	notifyWebSocket(userID)
	if s.Debug {
		log.Printf("[DEBUG] Updated service %s name to '%s' for user %s", req.ID, req.Name, userID)
	}

	c.JSON(200, gin.H{"message": "Service updated successfully"})
}

func (s *Server) handleCode(c *gin.Context) {
	userID := c.GetString("user_id")
	id := c.Query("id")
	name := c.Query("name")

	query := "SELECT id, user_id, name, key, created_at, updated_at FROM auth_service WHERE user_id = $1"
	args := []interface{}{userID}
	if id != "" {
		query += " AND id = $2"
		args = append(args, id)
	} else if name != "" {
		query += " AND name = $2"
		args = append(args, name)
	}

	rows, err := s.DB.QueryContext(c.Request.Context(), query, args...)
	if err != nil {
		if s.Debug {
			log.Printf("[DEBUG] Failed to query auth_service for code: %v", err)
		}
		c.JSON(500, gin.H{"error": "Failed to fetch services"})
		return
	}
	defer rows.Close()

	var codes []map[string]interface{}
	now := time.Now()
	expiresIn := 30 - (now.Unix() % 30)
	expiresAt := now.Add(time.Duration(expiresIn) * time.Second).UTC()
	for rows.Next() {
		var svc models.AuthService
		if err := rows.Scan(&svc.ID, &svc.UserID, &svc.Name, &svc.Key, &svc.CreatedAt, &svc.UpdatedAt); err != nil {
			if s.Debug {
				log.Printf("[DEBUG] Failed to scan auth_service for code: %v", err)
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
		codes = append(codes, map[string]interface{}{
			"id":         svc.ID,
			"name":       svc.Name,
			"code":       code,
			"expires_at": expiresAt.Format(time.RFC3339),
		})
	}
	c.JSON(200, codes)
}

func (s *Server) handleDelete(c *gin.Context) {
	userID := c.GetString("user_id")

	contentType := c.GetHeader("Content-Type")
	if strings.Contains(contentType, "application/json") {
		var req struct {
			All  bool        `json:"all"`
			ID   interface{} `json:"id"`
			Name interface{} `json:"name"`
		}

		if err := c.ShouldBindJSON(&req); err != nil {
			if s.Debug {
				log.Printf("[DEBUG] Invalid request body for delete: %v", err)
			}
			c.JSON(400, gin.H{"error": "Invalid request body"})
			return
		}

		query := "DELETE FROM auth_service WHERE user_id = $1"
		args := []interface{}{userID}

		if !req.All {
			if req.ID != nil {
				switch v := req.ID.(type) {
				case string:
					if v != "" {
						query += " AND id = $2"
						args = append(args, v)
					}
				case float64:
					idStr := fmt.Sprintf("%.0f", v)
					query += " AND id = $2"
					args = append(args, idStr)
				case []interface{}:
					if len(v) > 0 {
						placeholders := make([]string, len(v))
						for i := range v {
							placeholders[i] = fmt.Sprintf("$%d", i+2)
						}
						query += fmt.Sprintf(" AND id IN (%s)", strings.Join(placeholders, ","))
						args = append(args, v...)
					}
				default:
					c.JSON(400, gin.H{"error": "Invalid id type. Expected string, number, or array"})
					return
				}
			} else if req.Name != nil {
				switch v := req.Name.(type) {
				case string:
					if v != "" {
						query += " AND name = $2"
						args = append(args, v)
					}
				case float64:
					nameStr := fmt.Sprintf("%.0f", v)
					query += " AND name = $2"
					args = append(args, nameStr)
				case []interface{}:
					if len(v) > 0 {
						placeholders := make([]string, len(v))
						for i := range v {
							placeholders[i] = fmt.Sprintf("$%d", i+2)
						}
						query += fmt.Sprintf(" AND name IN (%s)", strings.Join(placeholders, ","))
						args = append(args, v...)
					}
				default:
					c.JSON(400, gin.H{"error": "Invalid name type. Expected string, number, or array"})
					return
				}
			} else {
				c.JSON(400, gin.H{"error": "Missing id, name, or all parameter"})
				return
			}
		}

		res, err := s.DB.ExecContext(c.Request.Context(), query, args...)
		if err != nil {
			if s.Debug {
				log.Printf("[DEBUG] Failed to delete auth_service: %v", err)
			}
			c.JSON(500, gin.H{"error": "Failed to delete services"})
			return
		}

		n, _ := res.RowsAffected()
		if n == 0 {
			c.JSON(404, gin.H{"error": "No services found or not owned by user"})
			return
		}

		notifyWebSocket(userID)
		if s.Debug {
			log.Printf("[DEBUG] Deleted %d services for user %s", n, userID)
		}

		c.JSON(200, gin.H{"message": "Deleted", "count": n})
	} else {
		id := c.Query("id")
		if id == "" {
			c.JSON(400, gin.H{"error": "Missing id parameter"})
			return
		}
		res, err := s.DB.ExecContext(c.Request.Context(), "DELETE FROM auth_service WHERE id = $1 AND user_id = $2", id, userID)
		if err != nil {
			if s.Debug {
				log.Printf("[DEBUG] Failed to delete auth_service: %v", err)
			}
			c.JSON(500, gin.H{"error": "Failed to delete service"})
			return
		}
		n, _ := res.RowsAffected()
		if n == 0 {
			c.JSON(404, gin.H{"error": "Service not found or not owned by user"})
			return
		}
		notifyWebSocket(userID)
		c.JSON(200, gin.H{"message": "Deleted"})
	}
}

func (s *Server) handleExport(c *gin.Context) {
	userID := c.GetString("user_id")

	var req struct {
		All  bool        `json:"all"`
		ID   interface{} `json:"id"`
		Name interface{} `json:"name"`
	}

	if err := c.ShouldBindJSON(&req); err != nil {
		if s.Debug {
			log.Printf("[DEBUG] Invalid request body for export: %v", err)
		}
		c.JSON(400, gin.H{"error": "Invalid request body"})
		return
	}

	query := "SELECT id, user_id, name, key FROM auth_service WHERE user_id = $1"
	args := []interface{}{userID}

	if !req.All {
		if req.ID != nil {
			switch v := req.ID.(type) {
			case string:
				if v != "" {
					query += " AND id = $2"
					args = append(args, v)
				}
			case float64:
				idStr := fmt.Sprintf("%.0f", v)
				query += " AND id = $2"
				args = append(args, idStr)
			case []interface{}:
				if len(v) > 0 {
					placeholders := make([]string, len(v))
					for i := range v {
						placeholders[i] = fmt.Sprintf("$%d", i+2)
					}
					query += fmt.Sprintf(" AND id IN (%s)", strings.Join(placeholders, ","))
					args = append(args, v...)
				}
			default:
				c.JSON(400, gin.H{"error": "Invalid id type. Expected string, number, or array"})
				return
			}
		} else if req.Name != nil {
			switch v := req.Name.(type) {
			case string:
				if v != "" {
					query += " AND name = $2"
					args = append(args, v)
				}
			case float64:
				nameStr := fmt.Sprintf("%.0f", v)
				query += " AND name = $2"
				args = append(args, nameStr)
			case []interface{}:
				if len(v) > 0 {
					placeholders := make([]string, len(v))
					for i := range v {
						placeholders[i] = fmt.Sprintf("$%d", i+2)
					}
					query += fmt.Sprintf(" AND name IN (%s)", strings.Join(placeholders, ","))
					args = append(args, v...)
				}
			default:
				c.JSON(400, gin.H{"error": "Invalid name type. Expected string, number, or array"})
				return
			}
		} else {
			c.JSON(400, gin.H{"error": "Missing id, name, or all parameter"})
			return
		}
	}

	rows, err := s.DB.QueryContext(c.Request.Context(), query, args...)
	if err != nil {
		if s.Debug {
			log.Printf("[DEBUG] Failed to fetch services for export: %v", err)
		}
		c.JSON(500, gin.H{"error": "Failed to fetch services"})
		return
	}
	defer rows.Close()

	var pairs [][2]string
	var services []map[string]interface{}

	for rows.Next() {
		var sid, suid, sname, skey string
		if err := rows.Scan(&sid, &suid, &sname, &skey); err != nil {
			continue
		}
		pairs = append(pairs, [2]string{sname, skey})
		services = append(services, map[string]interface{}{
			"id":   sid,
			"name": sname,
		})
	}

	if len(pairs) == 0 {
		c.JSON(404, gin.H{"error": "No services found or not owned by user"})
		return
	}

	// Generate otpauth-migration URL
	url, err := utils.GenerateMigrationURL(pairs)
	if err != nil {
		if s.Debug {
			log.Printf("[DEBUG] Failed to generate migration URL: %v", err)
		}
		c.JSON(500, gin.H{"error": "Failed to generate migration URL"})
		return
	}

	response := gin.H{
		"migration_url":  url,
		"services_count": len(services),
		"services":       services,
	}

	if s.Debug {
		log.Printf("[DEBUG] Exported %d services for user %s", len(services), userID)
	}

	c.JSON(200, response)
}

func (s *Server) withSession(next gin.HandlerFunc) gin.HandlerFunc {
	return func(c *gin.Context) {
		cookie, err := c.Request.Cookie("__Secure-better-auth.session_token")
		if err != nil {
			cookie, err = c.Request.Cookie("better-auth.session_token")
			if err != nil {
				cookie, err = c.Request.Cookie("session_token")
				if err != nil {
					if s.Debug {
						log.Printf("[DEBUG] Missing session token from %s", c.ClientIP())
					}
					c.JSON(http.StatusUnauthorized, gin.H{"error": "Missing session token"})
					c.Abort()
					return
				}
			}
		}
		token, valid := utils.VerifySignedCookie(cookie.Value, s.Secret)
		if !valid {
			if s.Debug {
				log.Printf("[DEBUG] Invalid session token from %s", c.ClientIP())
			}
			c.JSON(http.StatusUnauthorized, gin.H{"error": "Invalid session token"})
			c.Abort()
			return
		}
		userID, err := utils.GetUserIDFromToken(c.Request.Context(), s.DB, token)
		if err != nil {
			if s.Debug {
				log.Printf("[DEBUG] Session not found for token %s from %s", token, c.ClientIP())
			}
			c.JSON(http.StatusUnauthorized, gin.H{"error": "Session not found"})
			c.Abort()
			return
		}
		if s.Debug {
			log.Printf("[DEBUG] Authenticated request from %s with token %s (user_id: %s)", c.ClientIP(), cookie.Value, userID)
		}
		ctx := context.WithValue(c.Request.Context(), sessionTokenKey, token)
		c.Request = c.Request.WithContext(ctx)
		c.Set("user_id", userID)
		next(c)
	}
}

// extractTokenFromRawQuery extracts the raw (URL-encoded) value of a query parameter
func extractTokenFromRawQuery(rawQuery, paramName string) string {
	if rawQuery == "" {
		return ""
	}

	// Parse the raw query string manually to preserve URL encoding
	params := strings.Split(rawQuery, "&")
	for _, param := range params {
		if strings.HasPrefix(param, paramName+"=") {
			value := strings.TrimPrefix(param, paramName+"=")
			return value
		}
	}
	return ""
}
