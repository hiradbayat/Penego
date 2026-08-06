package routes

import (
	"net/http"

	"github.com/gin-gonic/gin"
	"penego/config"
	"penego/handlers"
	"penego/middlewares"
)

type Deps struct {
	Config     *config.Config
	Scan       *handlers.ScanHandler
	Pages      *handlers.PageHandler
	Auth       *handlers.AuthHandler
	Engagement *handlers.EngagementHandler
	Assets     http.FileSystem
}

func Register(r *gin.Engine, d Deps) {
	r.StaticFS("/assets", d.Assets)

	sessCfg := middlewares.SessionConfig{
		Secret:       d.Config.SessionSecret,
		Password:     d.Config.AdminPassword,
		AuthDisabled: d.Config.AuthDisabled,
		UseDBUsers:   d.Config.UseDBUsers,
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
		auth.GET("/engagements", d.Pages.Engagements)
		auth.GET("/engagements/:id", d.Pages.EngagementDetail)
		auth.GET("/enumeration", d.Pages.EnumPage)
		auth.GET("/path-trace", d.Pages.PathTracePage)
		auth.GET("/auth-check", d.Pages.AuthCheckPage)
		auth.GET("/assessment-pipeline", d.Pages.PipelinePage)

		api := auth.Group("/api")
		{
			api.POST("/scan", middlewares.RequireOperator(), d.Scan.ScanNetwork)
			api.POST("/host_discovery", middlewares.RequireOperator(), d.Scan.HostDiscovery)
			api.POST("/os_fingerprint", middlewares.RequireOperator(), d.Scan.OSFingerprint)
			api.POST("/vuln_scan", middlewares.RequireOperator(), d.Scan.VulnScan)
			api.POST("/path_trace", middlewares.RequireOperator(), d.Scan.PathTrace)
			api.POST("/udp_scan", middlewares.RequireOperator(), d.Scan.UDPScan)
			api.POST("/service_enum", middlewares.RequireOperator(), d.Scan.ServiceEnum)
			api.POST("/auth_check", middlewares.RequireOperator(), d.Scan.AuthCheck)
			api.POST("/assessment_pipeline", middlewares.RequireOperator(), d.Scan.AssessmentPipeline)
			api.GET("/scans", d.Scan.GetScanResults)
			api.GET("/scans/:id", d.Scan.GetScanByID)
			api.DELETE("/scans/:id", middlewares.RequireOperator(), d.Scan.DeleteScan)
			api.POST("/scans/:id/cancel", middlewares.RequireOperator(), d.Scan.CancelScan)
			api.GET("/scans/:id/export", d.Scan.ExportScanJSON)
			api.GET("/scans/:id/export.html", d.Scan.ExportScanHTML)
			api.GET("/network_map", d.Scan.NetworkMap)
			api.POST("/admin/purge", middlewares.RequireOperator(), d.Scan.PurgeDeleted)
			api.POST("/users", middlewares.RequireOperator(), d.Auth.CreateUser)

			api.GET("/engagements", d.Engagement.List)
			api.POST("/engagements", middlewares.RequireOperator(), d.Engagement.Create)
			api.GET("/engagements/:id", d.Engagement.Get)
			api.PATCH("/engagements/:id", middlewares.RequireOperator(), d.Engagement.Update)
			api.POST("/engagements/:id/close", middlewares.RequireOperator(), d.Engagement.Close)
			api.GET("/engagements/:id/findings", d.Engagement.ListFindings)
			api.PATCH("/engagements/:id/findings/:fid", middlewares.RequireOperator(), d.Engagement.UpdateFinding)
			api.GET("/engagements/:id/assets", d.Engagement.ListAssets)
			api.GET("/engagements/:id/export.html", d.Engagement.ExportHTML)
		}
	}
}
