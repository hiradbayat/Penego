package bootstrap

import (
	"fmt"
	"log"
	"os/exec"

	"gorm.io/driver/mysql"
	"gorm.io/gorm"
	"gorm.io/gorm/logger"
	"penego/models"
	"penego/services"
)

func ConnectDB(dsn string) (*gorm.DB, error) {
	db, err := gorm.Open(mysql.Open(dsn), &gorm.Config{
		Logger: logger.Default.LogMode(logger.Warn),
	})
	if err != nil {
		return nil, fmt.Errorf("connect database: %w", err)
	}
	return db, nil
}

func AutoMigrate(db *gorm.DB) error {
	return db.AutoMigrate(
		&models.ScanReport{},
		&models.HostResult{},
		&models.PortInfo{},
		&models.VulnFinding{},
		&models.AuditLog{},
	)
}

func CheckDependencies() {
	if services.CheckPingAvailable() {
		log.Println("dependency: ping OK")
	} else {
		log.Println("warning: ping not available — host discovery / OS alive-check may fail")
	}
	if services.CheckNmapAvailable() {
		log.Println("dependency: nmap OK")
	} else {
		log.Println("warning: nmap not available — OS fingerprinting will return Unknown")
	}
	if _, err := exec.LookPath("ping"); err != nil {
		log.Println("warning: ping not found on PATH")
	}
	if _, err := exec.LookPath("nmap"); err != nil {
		log.Println("warning: nmap not found on PATH")
	}
}
