package services

import (
	"fmt"

	"golang.org/x/crypto/bcrypt"
	"gorm.io/gorm"
	"penego/models"
)

func HashPassword(password string) (string, error) {
	b, err := bcrypt.GenerateFromPassword([]byte(password), bcrypt.DefaultCost)
	return string(b), err
}

func CheckPasswordHash(hash, password string) bool {
	return bcrypt.CompareHashAndPassword([]byte(hash), []byte(password)) == nil
}

func EnsureAdminUser(db *gorm.DB, username, password string) error {
	if username == "" {
		username = "admin"
	}
	if password == "" {
		password = "penego"
	}
	hash, err := HashPassword(password)
	if err != nil {
		return err
	}

	var u models.User
	err = db.Where("username = ?", username).First(&u).Error
	if err == gorm.ErrRecordNotFound {
		u = models.User{
			Username:     username,
			PasswordHash: hash,
			Role:         models.RoleOperator,
			Active:       true,
		}
		return db.Create(&u).Error
	}
	if err != nil {
		return err
	}

	// Keep admin password in sync with ADMIN_PASSWORD from env (lab convenience).
	updates := map[string]interface{}{
		"password_hash": hash,
		"active":        true,
		"role":          models.RoleOperator,
		"deleted_at":    nil,
	}
	return db.Unscoped().Model(&u).Updates(updates).Error
}

func AuthenticateUser(db *gorm.DB, username, password string) (*models.User, error) {
	var u models.User
	if err := db.Where("username = ? AND active = ?", username, true).First(&u).Error; err != nil {
		return nil, fmt.Errorf("invalid credentials")
	}
	if !CheckPasswordHash(u.PasswordHash, password) {
		return nil, fmt.Errorf("invalid credentials")
	}
	return &u, nil
}

func CreateUser(db *gorm.DB, username, password, role string) (*models.User, error) {
	if role != models.RoleOperator && role != models.RoleViewer {
		role = models.RoleViewer
	}
	hash, err := HashPassword(password)
	if err != nil {
		return nil, err
	}
	u := &models.User{Username: username, PasswordHash: hash, Role: role, Active: true}
	if err := db.Create(u).Error; err != nil {
		return nil, err
	}
	return u, nil
}

// PurgeSoftDeleted permanently removes soft-deleted scan graphs older than retention — simple full purge helper.
func PurgeSoftDeleted(db *gorm.DB) (int64, error) {
	var n int64
	res := db.Unscoped().Where("deleted_at IS NOT NULL").Delete(&models.ScanReport{})
	n += res.RowsAffected
	if res.Error != nil {
		return n, res.Error
	}
	_ = db.Unscoped().Where("deleted_at IS NOT NULL").Delete(&models.HostResult{})
	_ = db.Unscoped().Where("deleted_at IS NOT NULL").Delete(&models.PortInfo{})
	_ = db.Unscoped().Where("deleted_at IS NOT NULL").Delete(&models.Finding{})
	_ = db.Unscoped().Where("deleted_at IS NOT NULL").Delete(&models.Asset{})
	return n, nil
}
