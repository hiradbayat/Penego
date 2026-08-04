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
)

const (
	sessionCookie = "penego_session"
	sessionUser   = "admin"
	ctxUserKey    = "user"
)

type SessionConfig struct {
	Secret       string
	Password     string
	AuthDisabled bool
}

func Session(cfg SessionConfig) gin.HandlerFunc {
	return func(c *gin.Context) {
		if cfg.AuthDisabled {
			c.Set(ctxUserKey, "anonymous")
			c.Next()
			return
		}
		cookie, err := c.Cookie(sessionCookie)
		if err == nil && validSession(cookie, cfg.Secret) {
			c.Set(ctxUserKey, sessionUser)
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

func CurrentUser(c *gin.Context) string {
	if v, ok := c.Get(ctxUserKey); ok {
		if s, ok := v.(string); ok {
			return s
		}
	}
	return ""
}

func SetSessionCookie(c *gin.Context, secret string) {
	token := signSession(sessionUser, secret)
	c.SetCookie(sessionCookie, token, 86400*7, "/", "", false, true)
}

func ClearSessionCookie(c *gin.Context) {
	c.SetCookie(sessionCookie, "", -1, "/", "", false, true)
}

func CheckPassword(cfg SessionConfig, password string) bool {
	return password == cfg.Password
}

func signSession(user, secret string) string {
	payload := user + "|" + time.Now().UTC().Format("2006-01-02")
	mac := hmac.New(sha256.New, []byte(secret))
	mac.Write([]byte(payload))
	sig := base64.RawURLEncoding.EncodeToString(mac.Sum(nil))
	return base64.RawURLEncoding.EncodeToString([]byte(payload)) + "." + sig
}

func validSession(token, secret string) bool {
	parts := strings.Split(token, ".")
	if len(parts) != 2 {
		return false
	}
	raw, err := base64.RawURLEncoding.DecodeString(parts[0])
	if err != nil {
		return false
	}
	payload := string(raw)
	mac := hmac.New(sha256.New, []byte(secret))
	mac.Write([]byte(payload))
	expected := base64.RawURLEncoding.EncodeToString(mac.Sum(nil))
	if !hmac.Equal([]byte(expected), []byte(parts[1])) {
		return false
	}
	userDay := strings.SplitN(payload, "|", 2)
	if len(userDay) != 2 {
		return false
	}
	today := time.Now().UTC().Format("2006-01-02")
	yesterday := time.Now().UTC().Add(-24 * time.Hour).Format("2006-01-02")
	return userDay[1] == today || userDay[1] == yesterday
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
