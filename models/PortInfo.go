package models

import "gorm.io/gorm"

type PortInfo struct {
	gorm.Model
	Port         int    `json:"port"`
	Open         bool   `json:"open"`
	Service      string `json:"service,omitempty"`
	Banner       string `json:"banner,omitempty"`
	HostResultID uint   `gorm:"index" json:"host_result_id"`
}
