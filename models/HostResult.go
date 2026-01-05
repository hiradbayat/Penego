package models

import (
	"gorm.io/gorm"
)

type HostResult struct {
	ID        uint       `gorm:"primaryKey" json:"id"`
	IP        string     `gorm:"index" json:"ip"`
	Alive     bool       `json:"alive"`
	OpenPorts []PortInfo `gorm:"foreignKey:ScanID" json:"open_ports"`
	OS        string     `json:"os,omitempty"`
	ScanID    uint       `json:"scan_id"`
	gorm.Model
}
