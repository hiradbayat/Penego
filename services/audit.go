package services

import (
	"gorm.io/gorm"
	"penego/models"
)

func WriteAudit(db *gorm.DB, who, action, target, detail, ip string) {
	_ = db.Create(&models.AuditLog{
		Who:    who,
		Action: action,
		Target: target,
		Detail: detail,
		IP:     ip,
	}).Error
}
