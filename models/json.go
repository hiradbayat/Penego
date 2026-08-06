package models

import "time"

// ScanReportJSON is the API shape used by the UI (true_targets / false_targets).
type ScanReportJSON struct {
	ID           uint         `json:"id"`
	Generated    time.Time    `json:"generated"`
	ScanType     string       `json:"scan_type"`
	Status       string       `json:"status"`
	ErrorMessage string       `json:"error_message,omitempty"`
	Target       string       `json:"target"`
	PortsScanned string       `json:"ports_scanned"`
	Notes        string       `json:"notes,omitempty"`
	Progress     int          `json:"progress"`
	EngagementID *uint        `json:"engagement_id,omitempty"`
	TrueTargets  []HostResult `json:"true_targets"`
	FalseTargets []HostResult `json:"false_targets"`
	CreatedAt    time.Time    `json:"created_at,omitempty"`
	UpdatedAt    time.Time    `json:"updated_at,omitempty"`
}

func ToScanReportJSON(s ScanReport) ScanReportJSON {
	return ScanReportJSON{
		ID:           s.ID,
		Generated:    s.Generated,
		ScanType:     s.ScanType,
		Status:       s.Status,
		ErrorMessage: s.ErrorMessage,
		Target:       s.Target,
		PortsScanned: s.PortsScanned,
		Notes:        s.Notes,
		Progress:     s.Progress,
		EngagementID: s.EngagementID,
		TrueTargets:  s.TrueTargets(),
		FalseTargets: s.FalseTargets(),
		CreatedAt:    s.CreatedAt,
		UpdatedAt:    s.UpdatedAt,
	}
}

func ToScanReportJSONList(scans []ScanReport) []ScanReportJSON {
	out := make([]ScanReportJSON, 0, len(scans))
	for _, s := range scans {
		out = append(out, ToScanReportJSON(s))
	}
	return out
}
