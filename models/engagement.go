package models

import (
	"time"

	"gorm.io/gorm"
)

const (
	EngagementDraft  = "draft"
	EngagementActive = "active"
	EngagementClosed = "closed"
)

type Engagement struct {
	gorm.Model
	Name        string       `gorm:"size:255;not null" json:"name"`
	Description string       `gorm:"type:text" json:"description"`
	Status      string       `gorm:"index;size:32" json:"status"`
	ScopeCIDRs  string       `gorm:"type:text" json:"scope_cidrs"` // comma-separated IPs/CIDRs
	Notes       string       `gorm:"type:text" json:"notes,omitempty"`
	CreatedBy   string       `gorm:"size:128" json:"created_by,omitempty"`
	Scans       []ScanReport `gorm:"foreignKey:EngagementID" json:"scans,omitempty"`
	Assets      []Asset      `gorm:"foreignKey:EngagementID" json:"assets,omitempty"`
	Findings    []Finding    `gorm:"foreignKey:EngagementID" json:"findings,omitempty"`
}

type Asset struct {
	gorm.Model
	EngagementID uint      `gorm:"index;uniqueIndex:idx_eng_ip" json:"engagement_id"`
	IP           string    `gorm:"size:64;uniqueIndex:idx_eng_ip" json:"ip"`
	Hostname     string    `gorm:"size:255" json:"hostname,omitempty"`
	OS           string    `gorm:"size:255" json:"os,omitempty"`
	Tags         string    `gorm:"size:512" json:"tags,omitempty"`
	HTTPTitle    string    `gorm:"size:512" json:"http_title,omitempty"`
	TLSCN        string    `gorm:"size:512" json:"tls_cn,omitempty"`
	TLSSANs      string    `gorm:"type:text" json:"tls_sans,omitempty"`
	Traceroute   string    `gorm:"type:text" json:"traceroute,omitempty"`
	OpenPorts    string    `gorm:"type:text" json:"open_ports,omitempty"` // comma list cache
	LastSeen     time.Time `json:"last_seen"`
	Findings     []Finding `gorm:"foreignKey:AssetID" json:"findings,omitempty"`
}

const (
	FindingOpen     = "open"
	FindingFixed    = "fixed"
	FindingAccepted = "accepted"

	SeverityCritical = "critical"
	SeverityHigh     = "high"
	SeverityMedium   = "medium"
	SeverityLow      = "low"
	SeverityInfo     = "info"
)

type Finding struct {
	gorm.Model
	EngagementID uint   `gorm:"index" json:"engagement_id"`
	AssetID      *uint  `gorm:"index" json:"asset_id,omitempty"`
	HostResultID *uint  `gorm:"index" json:"host_result_id,omitempty"`
	Port         int    `json:"port,omitempty"`
	Severity     string `gorm:"index;size:32" json:"severity"`
	Status       string `gorm:"index;size:32" json:"status"`
	Title        string `gorm:"size:512" json:"title"`
	Description  string `gorm:"type:text" json:"description"`
	CVE          string `gorm:"size:64" json:"cve,omitempty"`
	Evidence     string `gorm:"type:text" json:"evidence,omitempty"`
	Remediation  string `gorm:"type:text" json:"remediation,omitempty"`
	Category     string `gorm:"size:64" json:"category,omitempty"` // vuln, auth, tls, enum
}

// User for multi-user lab auth
const (
	RoleOperator = "operator"
	RoleViewer   = "viewer"
)

type User struct {
	gorm.Model
	Username     string `gorm:"uniqueIndex;size:128" json:"username"`
	PasswordHash string `gorm:"size:255" json:"-"`
	Role         string `gorm:"size:32" json:"role"`
	Active       bool   `json:"active"`
}
