package models

import (
	"gorm.io/gorm"
)

type PortInfo struct {
	ID      uint   `gorm:"primaryKey" json:"id"`
	Port    int    `json:"port"`
	Open    bool   `json:"open"`
	Service string `json:"service,omitempty"`
	Banner  string `json:"banner,omitempty"`
	ScanID  uint   `json:"scan_id"`
	gorm.Model
}
