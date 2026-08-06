package models

import (
	"time"

	"gorm.io/gorm"
)

const (
	ScanTypePortScan      = "port_scan"
	ScanTypeHostDiscovery = "host_discovery"
	ScanTypeOSFingerprint = "os_fingerprint"
	ScanTypeVulnScan      = "vuln_scan"
	ScanTypePathTrace     = "path_trace"
	ScanTypeUDPScan       = "udp_scan"
	ScanTypeEnum          = "service_enum"
	ScanTypeAuthCheck     = "auth_check"
	ScanTypePipeline      = "assessment_pipeline"

	StatusPending   = "pending"
	StatusRunning   = "running"
	StatusDone      = "done"
	StatusFailed    = "failed"
	StatusCancelled = "cancelled"
)

type ScanReport struct {
	gorm.Model
	Generated    time.Time    `json:"generated"`
	ScanType     string       `gorm:"index;size:64" json:"scan_type"`
	Status       string       `gorm:"index;size:32" json:"status"`
	ErrorMessage string       `json:"error_message,omitempty"`
	Target       string       `json:"target"`
	PortsScanned string       `json:"ports_scanned"`
	Notes        string       `json:"notes,omitempty"`
	Progress     int          `json:"progress"`
	EngagementID *uint        `gorm:"index" json:"engagement_id,omitempty"`
	Hosts        []HostResult `gorm:"foreignKey:ScanID" json:"hosts"`
}

// TrueTargets filters alive hosts for API compatibility.
func (s ScanReport) TrueTargets() []HostResult {
	out := make([]HostResult, 0)
	for _, h := range s.Hosts {
		if h.Alive {
			out = append(out, h)
		}
	}
	return out
}

// FalseTargets filters non-alive hosts for API compatibility.
func (s ScanReport) FalseTargets() []HostResult {
	out := make([]HostResult, 0)
	for _, h := range s.Hosts {
		if !h.Alive {
			out = append(out, h)
		}
	}
	return out
}
