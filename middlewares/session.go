package middlewares

import (
	"crypto/hmac"
	"crypto/sha256"
	"encoding/base64"
	"net/http"
	"strings"
	"sync"
	"time"

	"github.com/gin-gonic/gin"
	"penego/models"
)

const (
	sessionCookie = "penego_session"
	ctxUserKey    = "user"
	ctxRoleKey    = "role"
)

type SessionConfig struct {
	Secret       string
	Password     string // legacy single-password fallback
	AuthDisabled bool
	UseDBUsers   bool
}

func Session(cfg SessionConfig) gin.HandlerFunc {
	return func(c *gin.Context) {
		if cfg.AuthDisabled {
			c.Set(ctxUserKey, "anonymous")
			c.Set(ctxRoleKey, models.RoleOperator)
			c.Next()
			return
		}
		cookie, err := c.Cookie(sessionCookie)
		if err == nil {
			if user, role, ok := parseSession(cookie, cfg.Secret); ok {
				c.Set(ctxUserKey, user)
				c.Set(ctxRoleKey, role)
			}
		}
		c.Next()
	}
}

func RequireAuth(cfg SessionConfig) gin.HandlerFunc {
	return func(c *gin.Context) {
		if cfg.AuthDisabled {
			c.Next()
			return
		}
		if CurrentUser(c) != "" {
			c.Next()
			return
		}
		if strings.HasPrefix(c.Request.URL.Path, "/api/") {
			c.AbortWithStatusJSON(http.StatusUnauthorized, gin.H{"error": "authentication required"})
			return
		}
		c.Redirect(http.StatusFound, "/login")
		c.Abort()
	}
}

func RequireOperator() gin.HandlerFunc {
	return func(c *gin.Context) {
		if CurrentRole(c) == models.RoleViewer {
			if strings.HasPrefix(c.Request.URL.Path, "/api/") {
				c.AbortWithStatusJSON(http.StatusForbidden, gin.H{"error": "operator role required"})
				return
			}
			c.AbortWithStatus(http.StatusForbidden)
			return
		}
		c.Next()
	}
}

func CurrentUser(c *gin.Context) string {
	if v, ok := c.Get(ctxUserKey); ok {
		if s, ok := v.(string); ok {
			return s
		}
	}
	return ""
}

func CurrentRole(c *gin.Context) string {
	if v, ok := c.Get(ctxRoleKey); ok {
		if s, ok := v.(string); ok {
			return s
		}
	}
	return models.RoleOperator
}

func SetSessionCookie(c *gin.Context, secret, username, role string) {
	token := signSession(username, role, secret)
	c.SetCookie(sessionCookie, token, 86400*7, "/", "", false, true)
}

func ClearSessionCookie(c *gin.Context) {
	c.SetCookie(sessionCookie, "", -1, "/", "", false, true)
}

func CheckPassword(cfg SessionConfig, password string) bool {
	return password == cfg.Password
}

func signSession(user, role, secret string) string {
	if role == "" {
		role = models.RoleOperator
	}
	payload := user + "|" + role + "|" + time.Now().UTC().Format("2006-01-02")
	mac := hmac.New(sha256.New, []byte(secret))
	mac.Write([]byte(payload))
	sig := base64.RawURLEncoding.EncodeToString(mac.Sum(nil))
	return base64.RawURLEncoding.EncodeToString([]byte(payload)) + "." + sig
}

func parseSession(token, secret string) (user, role string, ok bool) {
	parts := strings.Split(token, ".")
	if len(parts) != 2 {
		return "", "", false
	}
	raw, err := base64.RawURLEncoding.DecodeString(parts[0])
	if err != nil {
		return "", "", false
	}
	payload := string(raw)
	mac := hmac.New(sha256.New, []byte(secret))
	mac.Write([]byte(payload))
	expected := base64.RawURLEncoding.EncodeToString(mac.Sum(nil))
	if !hmac.Equal([]byte(expected), []byte(parts[1])) {
		return "", "", false
	}
	fields := strings.Split(payload, "|")
	today := time.Now().UTC().Format("2006-01-02")
	yesterday := time.Now().UTC().Add(-24 * time.Hour).Format("2006-01-02")
	if len(fields) == 2 {
		// legacy: user|day
		if fields[1] != today && fields[1] != yesterday {
			return "", "", false
		}
		return fields[0], models.RoleOperator, true
	}
	if len(fields) != 3 {
		return "", "", false
	}
	if fields[2] != today && fields[2] != yesterday {
		return "", "", false
	}
	return fields[0], fields[1], true
}

func validSession(token, secret string) bool {
	_, _, ok := parseSession(token, secret)
	return ok
}

func RateLimit(perMinute int) gin.HandlerFunc {
	if perMinute <= 0 {
		perMinute = 60
	}
	type bucket struct {
		count int
		start time.Time
	}
	var mu sync.Mutex
	buckets := map[string]*bucket{}

	return func(c *gin.Context) {
		ip := c.ClientIP()
		now := time.Now()
		mu.Lock()
		b, ok := buckets[ip]
		if !ok || now.Sub(b.start) > time.Minute {
			buckets[ip] = &bucket{count: 1, start: now}
			mu.Unlock()
			c.Next()
			return
		}
		b.count++
		if b.count > perMinute {
			mu.Unlock()
			c.AbortWithStatusJSON(http.StatusTooManyRequests, gin.H{"error": "rate limit exceeded"})
			return
		}
		mu.Unlock()
		c.Next()
	}
}
