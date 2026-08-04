package main

import (
	"embed"
	"html/template"
	"io/fs"
	"log"
	"net/http"

	"github.com/gin-gonic/gin"
	"penego/bootstrap"
	"penego/config"
	"penego/handlers"
	"penego/routes"
	"penego/services"
)

//go:embed templates/*
var templatesFS embed.FS

//go:embed assets/*
var assetsFS embed.FS

func main() {
	cfg, err := config.Load()
	if err != nil {
		log.Fatal(err)
	}

	bootstrap.CheckDependencies()

	db, err := bootstrap.ConnectDB(cfg.DatabaseDSN)
	if err != nil {
		log.Fatal(err)
	}
	if err := bootstrap.AutoMigrate(db); err != nil {
		log.Fatal("Failed to migrate database:", err)
	}

	jobs := services.NewJobManager(db, services.JobConfig{
		MaxHosts:        cfg.MaxHosts,
		MaxPorts:        cfg.MaxPorts,
		DefaultHostConc: cfg.DefaultHostConc,
		DefaultPortConc: cfg.DefaultPortConc,
	})

	scanHandler := handlers.NewScanHandler(db, jobs, cfg)
	pageHandler := handlers.NewPageHandler(cfg)
	authHandler := handlers.NewAuthHandler(cfg)

	router := gin.Default()

	assetsSub, err := fs.Sub(assetsFS, "assets")
	if err != nil {
		log.Fatal("Failed to create assets sub filesystem:", err)
	}

	tmpl := template.Must(template.ParseFS(templatesFS, "templates/*.html"))
	router.SetHTMLTemplate(tmpl)

	routes.Register(router, routes.Deps{
		Config: cfg,
		Scan:   scanHandler,
		Pages:  pageHandler,
		Auth:   authHandler,
		Assets: http.FS(assetsSub),
	})

	log.Println("Server starting on", cfg.ListenAddr)
	if err := router.Run(cfg.ListenAddr); err != nil {
		log.Fatal("Failed to start server:", err)
	}
}
