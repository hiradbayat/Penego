package models

import "gorm.io/gorm"

type HostResult struct {
	gorm.Model
	IP           string        `gorm:"index" json:"ip"`
	Alive        bool          `json:"alive"`
	OS           string        `json:"os,omitempty"`
	ScanID       uint          `gorm:"index" json:"scan_id"`
	OpenPorts    []PortInfo    `gorm:"foreignKey:HostResultID" json:"open_ports"`
	VulnFindings []VulnFinding `gorm:"foreignKey:HostResultID" json:"vuln_findings,omitempty"`
}
