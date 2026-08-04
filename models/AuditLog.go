package models

import "gorm.io/gorm"

type AuditLog struct {
	gorm.Model
	Who    string `gorm:"index;size:128" json:"who"`
	Action string `gorm:"index;size:128" json:"action"`
	Target string `json:"target"`
	Detail string `json:"detail,omitempty"`
	IP     string `json:"ip,omitempty"`
}
