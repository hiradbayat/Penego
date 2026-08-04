package routes

import (
	"net/http"

	"github.com/gin-gonic/gin"
	"penego/config"
	"penego/handlers"
	"penego/middlewares"
)

type Deps struct {
	Config *config.Config
	Scan   *handlers.ScanHandler
	Pages  *handlers.PageHandler
	Auth   *handlers.AuthHandler
	Assets http.FileSystem
}

func Register(r *gin.Engine, d Deps) {
	r.StaticFS("/assets", d.Assets)

	sessCfg := middlewares.SessionConfig{
		Secret:       d.Config.SessionSecret,
		Password:     d.Config.AdminPassword,
		AuthDisabled: d.Config.AuthDisabled,
	}

	r.Use(middlewares.Session(sessCfg))
	r.Use(middlewares.RateLimit(d.Config.RateLimitPerMin))

	r.GET("/login", d.Auth.LoginPage)
	r.POST("/login", d.Auth.Login)
	r.GET("/logout", d.Auth.Logout)

	auth := r.Group("/")
	auth.Use(middlewares.RequireAuth(sessCfg))
	{
		auth.GET("/", d.Pages.PortScan)
		auth.GET("/host-discovery", d.Pages.HostDiscovery)
		auth.GET("/os-fingerprinting", d.Pages.OSFingerprint)
		auth.GET("/vulnerability-scanning", d.Pages.VulnScan)
		auth.GET("/network-mapping", d.Pages.NetworkMapping)

		api := auth.Group("/api")
		{
			api.POST("/scan", d.Scan.ScanNetwork)
			api.POST("/host_discovery", d.Scan.HostDiscovery)
			api.POST("/os_fingerprint", d.Scan.OSFingerprint)
			api.POST("/vuln_scan", d.Scan.VulnScan)
			api.GET("/scans", d.Scan.GetScanResults)
			api.GET("/scans/:id", d.Scan.GetScanByID)
			api.DELETE("/scans/:id", d.Scan.DeleteScan)
			api.POST("/scans/:id/cancel", d.Scan.CancelScan)
			api.GET("/scans/:id/export", d.Scan.ExportScanJSON)
			api.GET("/scans/:id/export.html", d.Scan.ExportScanHTML)
			api.GET("/network_map", d.Scan.NetworkMap)
		}
	}
}
