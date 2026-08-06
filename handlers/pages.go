package handlers

import (
	"net/http"
	"strings"

	"github.com/gin-gonic/gin"
	"gorm.io/gorm"
	"penego/config"
	"penego/middlewares"
	"penego/models"
	"penego/services"
)

type AuthHandler struct {
	Config *config.Config
	DB     *gorm.DB
}

func NewAuthHandler(cfg *config.Config, db *gorm.DB) *AuthHandler {
	return &AuthHandler{Config: cfg, DB: db}
}

func (h *AuthHandler) LoginPage(c *gin.Context) {
	c.HTML(http.StatusOK, "login.html", gin.H{
		"title":         "Login",
		"active":        "",
		"auth_disabled": h.Config.AuthDisabled,
		"use_db_users":  h.Config.UseDBUsers,
	})
}

func (h *AuthHandler) Login(c *gin.Context) {
	username := strings.TrimSpace(c.PostForm("username"))
	password := c.PostForm("password")
	if password == "" && username == "" {
		var req struct {
			Username string `json:"username"`
			Password string `json:"password"`
		}
		_ = c.ShouldBindJSON(&req)
		password = req.Password
		username = strings.TrimSpace(req.Username)
	}
	if password == "" {
		c.HTML(http.StatusBadRequest, "login.html", gin.H{
			"title": "Login", "error": "password required", "auth_disabled": h.Config.AuthDisabled, "use_db_users": h.Config.UseDBUsers,
		})
		return
	}
	if username == "" {
		username = "admin"
	}

	user := username
	role := models.RoleOperator
	ok := false

	if h.Config.UseDBUsers && h.DB != nil {
		if u, err := services.AuthenticateUser(h.DB, username, password); err == nil {
			user = u.Username
			role = u.Role
			ok = true
		}
	}
	// Always allow env ADMIN_PASSWORD for the admin account (even if DB hash is stale).
	if !ok && username == "admin" && password == h.Config.AdminPassword {
		user = "admin"
		role = models.RoleOperator
		ok = true
		// Repair DB hash so future logins work via AuthenticateUser.
		if h.Config.UseDBUsers && h.DB != nil {
			_ = services.EnsureAdminUser(h.DB, "admin", h.Config.AdminPassword)
		}
	}
	if !ok && !(h.Config.UseDBUsers && h.DB != nil) && password == h.Config.AdminPassword {
		ok = true
	}

	if !ok {
		if c.ContentType() == "application/json" {
			c.JSON(http.StatusUnauthorized, gin.H{"error": "invalid credentials"})
			return
		}
		c.HTML(http.StatusUnauthorized, "login.html", gin.H{
			"title": "Login", "error": "invalid credentials — use username admin and the value of ADMIN_PASSWORD from .env (default: penego)",
			"auth_disabled": h.Config.AuthDisabled, "use_db_users": h.Config.UseDBUsers,
		})
		return
	}

	middlewares.SetSessionCookie(c, h.Config.SessionSecret, user, role)
	if c.ContentType() == "application/json" {
		c.JSON(http.StatusOK, gin.H{"message": "logged in", "user": user, "role": role})
		return
	}
	c.Redirect(http.StatusFound, "/engagements")
}

func (h *AuthHandler) Logout(c *gin.Context) {
	middlewares.ClearSessionCookie(c)
	c.Redirect(http.StatusFound, "/login")
}

func (h *AuthHandler) CreateUser(c *gin.Context) {
	if middlewares.CurrentRole(c) == models.RoleViewer {
		c.JSON(http.StatusForbidden, gin.H{"error": "operators only"})
		return
	}
	var req struct {
		Username string `json:"username"`
		Password string `json:"password"`
		Role     string `json:"role"`
	}
	if err := c.ShouldBindJSON(&req); err != nil {
		c.JSON(http.StatusBadRequest, gin.H{"error": err.Error()})
		return
	}
	u, err := services.CreateUser(h.DB, req.Username, req.Password, req.Role)
	if err != nil {
		c.JSON(http.StatusBadRequest, gin.H{"error": err.Error()})
		return
	}
	c.JSON(http.StatusCreated, gin.H{"id": u.ID, "username": u.Username, "role": u.Role})
}

type PageHandler struct {
	Config *config.Config
}

func NewPageHandler(cfg *config.Config) *PageHandler {
	return &PageHandler{Config: cfg}
}

func (h *PageHandler) pageData(active, title, scanType, historyTitle string) gin.H {
	return gin.H{
		"title":             title,
		"active":            active,
		"auth_disabled":     h.Config.AuthDisabled,
		"scan_type":         scanType,
		"history_title":     historyTitle,
		"authcheck_enabled": h.Config.AuthCheckEnabled,
	}
}

func (h *PageHandler) PortScan(c *gin.Context) {
	c.HTML(http.StatusOK, "index.html", h.pageData("port", "Port Scanner", "port_scan", "Previous Scans"))
}

func (h *PageHandler) HostDiscovery(c *gin.Context) {
	c.HTML(http.StatusOK, "host_discovery.html", h.pageData("discovery", "Host Discovery", "host_discovery", "Previous Discoveries"))
}

func (h *PageHandler) OSFingerprint(c *gin.Context) {
	c.HTML(http.StatusOK, "os_fingerprint.html", h.pageData("os", "OS Fingerprinting", "os_fingerprint", "Previous Fingerprints"))
}

func (h *PageHandler) VulnScan(c *gin.Context) {
	c.HTML(http.StatusOK, "vuln_scan.html", h.pageData("vuln", "Vulnerability Scanning", "vuln_scan", "Previous Vuln Scans"))
}

func (h *PageHandler) NetworkMapping(c *gin.Context) {
	c.HTML(http.StatusOK, "network_mapping.html", h.pageData("map", "Network Mapping", "", ""))
}

func (h *PageHandler) Engagements(c *gin.Context) {
	c.HTML(http.StatusOK, "engagements.html", h.pageData("engagements", "Engagements", "", ""))
}

func (h *PageHandler) EngagementDetail(c *gin.Context) {
	data := h.pageData("engagements", "Engagement", "", "")
	data["engagement_id"] = c.Param("id")
	c.HTML(http.StatusOK, "engagement_detail.html", data)
}

func (h *PageHandler) EnumPage(c *gin.Context) {
	c.HTML(http.StatusOK, "enum.html", h.pageData("enum", "Service Enumeration", "service_enum", "Previous Enum Jobs"))
}

func (h *PageHandler) PathTracePage(c *gin.Context) {
	c.HTML(http.StatusOK, "path_trace.html", h.pageData("path", "Path / Traceroute", "path_trace", "Previous Path Traces"))
}

func (h *PageHandler) AuthCheckPage(c *gin.Context) {
	c.HTML(http.StatusOK, "auth_check.html", h.pageData("auth", "Credential Check", "auth_check", "Previous Auth Checks"))
}

func (h *PageHandler) PipelinePage(c *gin.Context) {
	c.HTML(http.StatusOK, "pipeline.html", h.pageData("pipeline", "Assessment Pipeline", "assessment_pipeline", "Previous Pipelines"))
}
