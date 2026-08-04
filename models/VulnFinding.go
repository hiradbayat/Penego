package models

import "gorm.io/gorm"

type VulnFinding struct {
	gorm.Model
	HostResultID uint   `gorm:"index" json:"host_result_id"`
	Port         int    `json:"port,omitempty"`
	Severity     string `json:"severity"`
	Title        string `json:"title"`
	Description  string `json:"description"`
	CVE          string `json:"cve,omitempty"`
	Evidence     string `json:"evidence,omitempty"`
}
