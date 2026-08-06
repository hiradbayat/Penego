package services

import (
	"fmt"
	"net"
	"strings"
	"time"

	"gorm.io/gorm"
	"penego/models"
)

func CreateEngagement(db *gorm.DB, name, description, scope, notes, createdBy string) (*models.Engagement, error) {
	name = strings.TrimSpace(name)
	if name == "" {
		return nil, fmt.Errorf("name is required")
	}
	if err := ValidateScopeList(scope); err != nil {
		return nil, err
	}
	e := &models.Engagement{
		Name:        name,
		Description: description,
		Status:      models.EngagementActive,
		ScopeCIDRs:  strings.TrimSpace(scope),
		Notes:       notes,
		CreatedBy:   createdBy,
	}
	if err := db.Create(e).Error; err != nil {
		return nil, err
	}
	return e, nil
}

func ValidateScopeList(scope string) error {
	scope = strings.TrimSpace(scope)
	if scope == "" {
		return nil
	}
	for _, part := range strings.Split(scope, ",") {
		part = strings.TrimSpace(part)
		if part == "" {
			continue
		}
		if err := ValidateTarget(part); err != nil {
			return fmt.Errorf("invalid scope entry %q: %w", part, err)
		}
	}
	return nil
}

func ParseScopeList(scope string) []string {
	out := make([]string, 0)
	for _, part := range strings.Split(scope, ",") {
		part = strings.TrimSpace(part)
		if part != "" {
			out = append(out, part)
		}
	}
	return out
}

// TargetInScope returns true if target IP/CIDR overlaps engagement scope.
// Empty scope means unrestricted (lab convenience).
func TargetInScope(scope string, target string) bool {
	entries := ParseScopeList(scope)
	if len(entries) == 0 {
		return true
	}
	target = strings.TrimSpace(target)
	if target == "" {
		return false
	}

	var targetNets []*net.IPNet
	if strings.Contains(target, "/") {
		_, n, err := net.ParseCIDR(target)
		if err != nil {
			return false
		}
		targetNets = []*net.IPNet{n}
	} else {
		ip := net.ParseIP(target)
		if ip == nil {
			return false
		}
		if v4 := ip.To4(); v4 != nil {
			targetNets = []*net.IPNet{{IP: v4, Mask: net.CIDRMask(32, 32)}}
		} else {
			targetNets = []*net.IPNet{{IP: ip, Mask: net.CIDRMask(128, 128)}}
		}
	}

	for _, entry := range entries {
		var scopeNet *net.IPNet
		if strings.Contains(entry, "/") {
			_, n, err := net.ParseCIDR(entry)
			if err != nil {
				continue
			}
			scopeNet = n
		} else {
			ip := net.ParseIP(entry)
			if ip == nil {
				continue
			}
			if v4 := ip.To4(); v4 != nil {
				scopeNet = &net.IPNet{IP: v4, Mask: net.CIDRMask(32, 32)}
			} else {
				scopeNet = &net.IPNet{IP: ip, Mask: net.CIDRMask(128, 128)}
			}
		}
		for _, tn := range targetNets {
			if scopeNet.Contains(tn.IP) || tn.Contains(scopeNet.IP) {
				return true
			}
		}
	}
	return false
}

func UpsertAssetsFromHosts(db *gorm.DB, engagementID uint, hosts []models.HostResult) error {
	now := time.Now()
	for _, h := range hosts {
		if !h.Alive {
			continue
		}
		ports := make([]string, 0, len(h.OpenPorts))
		for _, p := range h.OpenPorts {
			ports = append(ports, fmt.Sprintf("%d", p.Port))
		}
		var asset models.Asset
		err := db.Where("engagement_id = ? AND ip = ?", engagementID, h.IP).First(&asset).Error
		if err == gorm.ErrRecordNotFound {
			asset = models.Asset{
				EngagementID: engagementID,
				IP:           h.IP,
				OS:           h.OS,
				OpenPorts:    strings.Join(ports, ","),
				LastSeen:     now,
			}
			if err := db.Create(&asset).Error; err != nil {
				return err
			}
			continue
		}
		if err != nil {
			return err
		}
		updates := map[string]interface{}{
			"last_seen": now,
		}
		if h.OS != "" {
			updates["os"] = h.OS
		}
		if len(ports) > 0 {
			updates["open_ports"] = strings.Join(ports, ",")
		}
		if err := db.Model(&asset).Updates(updates).Error; err != nil {
			return err
		}
	}
	return nil
}

func UpdateAssetEnum(db *gorm.DB, engagementID uint, ip string, fields map[string]interface{}) error {
	fields["last_seen"] = time.Now()
	res := db.Model(&models.Asset{}).Where("engagement_id = ? AND ip = ?", engagementID, ip).Updates(fields)
	if res.Error != nil {
		return res.Error
	}
	if res.RowsAffected == 0 {
		asset := models.Asset{EngagementID: engagementID, IP: ip, LastSeen: time.Now()}
		if err := db.Create(&asset).Error; err != nil {
			return err
		}
		return db.Model(&asset).Updates(fields).Error
	}
	return nil
}
