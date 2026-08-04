package handlers

import (
	"net/http"

	"github.com/gin-gonic/gin"
	"penego/config"
	"penego/middlewares"
)

type AuthHandler struct {
	Config *config.Config
}

func NewAuthHandler(cfg *config.Config) *AuthHandler {
	return &AuthHandler{Config: cfg}
}

func (h *AuthHandler) LoginPage(c *gin.Context) {
	c.HTML(http.StatusOK, "login.html", gin.H{
		"title":         "Login",
		"active":        "",
		"auth_disabled": h.Config.AuthDisabled,
	})
}

func (h *AuthHandler) Login(c *gin.Context) {
	password := c.PostForm("password")
	if password == "" {
		var req struct {
			Password string `json:"password"`
		}
		_ = c.ShouldBindJSON(&req)
		password = req.Password
	}
	if password == "" {
		c.HTML(http.StatusBadRequest, "login.html", gin.H{
			"title": "Login", "error": "password required", "auth_disabled": h.Config.AuthDisabled,
		})
		return
	}
	cfg := middlewares.SessionConfig{
		Secret:       h.Config.SessionSecret,
		Password:     h.Config.AdminPassword,
		AuthDisabled: h.Config.AuthDisabled,
	}
	if !middlewares.CheckPassword(cfg, password) {
		if c.ContentType() == "application/json" {
			c.JSON(http.StatusUnauthorized, gin.H{"error": "invalid password"})
			return
		}
		c.HTML(http.StatusUnauthorized, "login.html", gin.H{
			"title": "Login", "error": "invalid password", "auth_disabled": h.Config.AuthDisabled,
		})
		return
	}
	middlewares.SetSessionCookie(c, h.Config.SessionSecret)
	if c.ContentType() == "application/json" {
		c.JSON(http.StatusOK, gin.H{"message": "logged in"})
		return
	}
	c.Redirect(http.StatusFound, "/")
}

func (h *AuthHandler) Logout(c *gin.Context) {
	middlewares.ClearSessionCookie(c)
	c.Redirect(http.StatusFound, "/login")
}

type PageHandler struct {
	Config *config.Config
}

func NewPageHandler(cfg *config.Config) *PageHandler {
	return &PageHandler{Config: cfg}
}

func (h *PageHandler) pageData(active, title string) gin.H {
	return gin.H{
		"title":         title,
		"active":        active,
		"auth_disabled": h.Config.AuthDisabled,
	}
}

func (h *PageHandler) PortScan(c *gin.Context) {
	c.HTML(http.StatusOK, "index.html", h.pageData("port", "Port Scanner"))
}

func (h *PageHandler) HostDiscovery(c *gin.Context) {
	c.HTML(http.StatusOK, "host_discovery.html", h.pageData("discovery", "Host Discovery"))
}

func (h *PageHandler) OSFingerprint(c *gin.Context) {
	c.HTML(http.StatusOK, "os_fingerprint.html", h.pageData("os", "OS Fingerprinting"))
}

func (h *PageHandler) VulnScan(c *gin.Context) {
	c.HTML(http.StatusOK, "vuln_scan.html", h.pageData("vuln", "Vulnerability Scanning"))
}

func (h *PageHandler) NetworkMapping(c *gin.Context) {
	c.HTML(http.StatusOK, "network_mapping.html", h.pageData("map", "Network Mapping"))
}
