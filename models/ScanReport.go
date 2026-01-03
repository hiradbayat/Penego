package models

import (
	"time"

	"gorm.io/gorm"
)

type ScanReport struct {
	ID           uint         `gorm:"primaryKey" json:"id"`
	Generated    time.Time    `json:"generated"`
	TrueTargets  []HostResult `gorm:"foreignKey:ScanID" json:"true_targets"`
	FalseTargets []HostResult `gorm:"foreignKey:ScanID" json:"false_targets"`
	Target       string       `json:"target"` // Original target (IP or CIDR)
	PortsScanned string       `json:"ports_scanned"`
	Notes        string       `json:"notes,omitempty"`
	gorm.Model
}
