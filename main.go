package main

import (
	"github.com/gin-gonic/gin"
	"gorm.io/driver/mysql"
	"gorm.io/gorm"
	"log"
	"penego/handlers"
	"penego/models"
)

func main() {
	// MySQL connection - update with your credentials
	dsn := "root:Hirad1375@tcp(127.0.0.1:3306)/gonet?charset=utf8mb4&parseTime=True&loc=Local"
	db, err := gorm.Open(mysql.Open(dsn), &gorm.Config{})
	if err != nil {
		log.Fatal("Failed to connect to database:", err)
	}

	// Auto migrate tables
	err = db.AutoMigrate(&models.ScanReport{}, &models.HostResult{}, &models.PortInfo{})
	if err != nil {
		log.Fatal("Failed to migrate database:", err)
	}

	// Initialize handler
	scanHandler := handlers.NewScanHandler(db)

	// Setup Gin router
	router := gin.Default()

	// Serve static files (CSS, JS, images)
	router.Static("/assets", "./assets")

	// Set up templates
	router.LoadHTMLGlob("templates/*")

	// Routes
	router.GET("/", scanHandler.ServeHTML)
	router.POST("/api/scan", scanHandler.ScanNetwork)
	router.GET("/api/scans", scanHandler.GetScanResults)
	router.GET("/api/scans/:id", scanHandler.GetScanByID)

	// Start server
	log.Println("Server starting on :8080")
	if err := router.Run(":8585"); err != nil {
		log.Fatal("Failed to start server:", err)
	}
}
