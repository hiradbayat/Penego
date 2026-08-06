package services

import (
	"context"
	"fmt"
	"strings"
	"sync"
	"time"

	"gorm.io/gorm"
	"penego/models"
)

type JobManager struct {
	db      *gorm.DB
	mu      sync.Mutex
	cancels map[uint]context.CancelFunc
	cfg     JobConfig
}

type JobConfig struct {
	MaxHosts           int
	MaxPorts           int
	DefaultHostConc    int
	DefaultPortConc    int
	AuthCheckEnabled   bool
	AuthCheckPerMinute int
	EnforceScope       bool
}

func NewJobManager(db *gorm.DB, cfg JobConfig) *JobManager {
	return &JobManager{
		db:      db,
		cancels: make(map[uint]context.CancelFunc),
		cfg:     cfg,
	}
}

type StartRequest struct {
	ScanType        string
	Target          string
	Ports           string
	HostConcurrency int
	PortConcurrency int
	TimeoutMs       int
	GrabBanner      bool
	Notes           string
	SourceScanID    uint
	EngagementID    *uint
	// Auth check fields
	AuthService  string
	AuthUsername string
	AuthPassword string
	AuthPort     int
}

func (j *JobManager) Start(req StartRequest) (*models.ScanReport, error) {
	if req.HostConcurrency <= 0 {
		req.HostConcurrency = j.cfg.DefaultHostConc
	}
	if req.PortConcurrency <= 0 {
		req.PortConcurrency = j.cfg.DefaultPortConc
	}
	if req.ScanType == models.ScanTypeAuthCheck {
		if !j.cfg.AuthCheckEnabled {
			return nil, fmt.Errorf("auth checks disabled (set AUTHCHECK_ENABLED=true)")
		}
		if req.AuthUsername == "" || req.AuthService == "" {
			return nil, fmt.Errorf("auth_service and username required")
		}
	}

	if req.EngagementID != nil && j.cfg.EnforceScope {
		var eng models.Engagement
		if err := j.db.First(&eng, *req.EngagementID).Error; err != nil {
			return nil, fmt.Errorf("engagement not found")
		}
		if eng.Status == models.EngagementClosed {
			return nil, fmt.Errorf("engagement is closed")
		}
		if req.Target != "" && req.Target != "from-existing-scan" && !TargetInScope(eng.ScopeCIDRs, req.Target) {
			return nil, fmt.Errorf("target %s outside engagement scope", req.Target)
		}
	}

	report := models.ScanReport{
		Generated:    time.Now(),
		ScanType:     req.ScanType,
		Status:       models.StatusPending,
		Target:       req.Target,
		PortsScanned: req.Ports,
		Notes:        req.Notes,
		Progress:     0,
		EngagementID: req.EngagementID,
	}
	switch req.ScanType {
	case models.ScanTypeHostDiscovery:
		report.PortsScanned = "Host Discovery"
	case models.ScanTypeOSFingerprint:
		report.PortsScanned = "OS Fingerprinting"
	case models.ScanTypePathTrace:
		report.PortsScanned = "Traceroute"
	case models.ScanTypeEnum:
		if report.PortsScanned == "" {
			report.PortsScanned = "80,443,445,8080,8443"
		}
	case models.ScanTypeUDPScan:
		if report.PortsScanned == "" {
			report.PortsScanned = "udp:53,123,161,500,514,1900,5353"
		}
	case models.ScanTypePipeline:
		if report.PortsScanned == "" {
			report.PortsScanned = "21,22,23,25,53,80,110,139,443,445,993,995,3306,3389,5432,8080,8443"
		}
	case models.ScanTypeAuthCheck:
		report.PortsScanned = fmt.Sprintf("%s/%d", req.AuthService, req.AuthPort)
	case models.ScanTypeVulnScan:
		if report.PortsScanned == "" {
			report.PortsScanned = "21,22,23,25,80,443,3306,5432,8080,8443"
		}
	}

	if err := j.db.Create(&report).Error; err != nil {
		return nil, err
	}

	ctx, cancel := context.WithCancel(context.Background())
	j.mu.Lock()
	j.cancels[report.ID] = cancel
	j.mu.Unlock()

	go j.run(ctx, report.ID, req)
	return &report, nil
}

func (j *JobManager) Cancel(id uint) error {
	j.mu.Lock()
	cancel, ok := j.cancels[id]
	j.mu.Unlock()
	if !ok {
		return fmt.Errorf("scan not running")
	}
	cancel()
	_ = j.db.Model(&models.ScanReport{}).Where("id = ?", id).Updates(map[string]interface{}{
		"status": models.StatusCancelled,
	}).Error
	return nil
}

func (j *JobManager) run(ctx context.Context, id uint, req StartRequest) {
	defer func() {
		j.mu.Lock()
		delete(j.cancels, id)
		j.mu.Unlock()
	}()

	_ = j.db.Model(&models.ScanReport{}).Where("id = ?", id).Updates(map[string]interface{}{
		"status": models.StatusRunning,
	}).Error

	opts := ScanOptions{
		Target:          req.Target,
		Ports:           req.Ports,
		HostConcurrency: req.HostConcurrency,
		PortConcurrency: req.PortConcurrency,
		TimeoutMs:       req.TimeoutMs,
		GrabBanner:      req.GrabBanner,
		MaxHosts:        j.cfg.MaxHosts,
		MaxPorts:        j.cfg.MaxPorts,
		Notes:           req.Notes,
	}

	onProgress := func(done, total int) {
		pct := 0
		if total > 0 {
			pct = done * 100 / total
			if pct > 100 {
				pct = 100
			}
		}
		_ = j.db.Model(&models.ScanReport{}).Where("id = ?", id).Update("progress", pct).Error
	}

	var result *models.ScanReport
	var err error
	var authFinding *models.Finding

	switch req.ScanType {
	case models.ScanTypePortScan:
		result, err = RunPortScan(ctx, opts, onProgress)
	case models.ScanTypeHostDiscovery:
		result, err = RunHostDiscovery(ctx, opts, onProgress)
	case models.ScanTypeOSFingerprint:
		result, err = RunOSFingerprint(ctx, opts, onProgress)
	case models.ScanTypeVulnScan:
		if req.SourceScanID > 0 {
			result, err = j.vulnFromExisting(ctx, id, req.SourceScanID)
		} else {
			result, err = RunVulnScan(ctx, opts, onProgress)
		}
	case models.ScanTypePathTrace:
		result, err = RunPathTrace(ctx, opts, onProgress)
	case models.ScanTypeUDPScan:
		result, err = RunUDPScan(ctx, opts, onProgress)
	case models.ScanTypeEnum:
		result, err = RunServiceEnum(ctx, opts, onProgress)
	case models.ScanTypePipeline:
		result, err = RunAssessmentPipeline(ctx, opts, onProgress)
	case models.ScanTypeAuthCheck:
		result, err = RunAuthCheckJob(ctx, opts, req.AuthUsername, req.AuthPassword, req.AuthService, req.AuthPort, onProgress)
		if err == nil {
			r := RunAuthCheck(AuthCheckRequest{
				Host: req.Target, Port: req.AuthPort, Service: req.AuthService,
				Username: req.AuthUsername, Password: req.AuthPassword,
				Timeout: time.Duration(opts.TimeoutMs) * time.Millisecond,
			})
			authFinding = &r.Finding
		}
	default:
		err = fmt.Errorf("unknown scan type: %s", req.ScanType)
	}

	if err != nil {
		status := models.StatusFailed
		if ctx.Err() != nil {
			status = models.StatusCancelled
		}
		_ = j.db.Model(&models.ScanReport{}).Where("id = ?", id).Updates(map[string]interface{}{
			"status":        status,
			"error_message": err.Error(),
		}).Error
		return
	}

	for i := range result.Hosts {
		result.Hosts[i].ID = 0
		result.Hosts[i].ScanID = id
		for k := range result.Hosts[i].OpenPorts {
			result.Hosts[i].OpenPorts[k].ID = 0
			result.Hosts[i].OpenPorts[k].HostResultID = 0
		}
		for k := range result.Hosts[i].VulnFindings {
			result.Hosts[i].VulnFindings[k].ID = 0
			result.Hosts[i].VulnFindings[k].HostResultID = 0
		}
	}
	if len(result.Hosts) > 0 {
		if err := j.db.Create(&result.Hosts).Error; err != nil {
			_ = j.db.Model(&models.ScanReport{}).Where("id = ?", id).Updates(map[string]interface{}{
				"status":        models.StatusFailed,
				"error_message": err.Error(),
			}).Error
			return
		}
	}

	if req.EngagementID != nil {
		_ = UpsertAssetsFromHosts(j.db, *req.EngagementID, result.Hosts)
		j.postProcessEngagement(*req.EngagementID, result, authFinding)
	}

	_ = j.db.Model(&models.ScanReport{}).Where("id = ?", id).Updates(map[string]interface{}{
		"status":   models.StatusDone,
		"progress": 100,
	}).Error
}

func (j *JobManager) postProcessEngagement(engID uint, result *models.ScanReport, authFinding *models.Finding) {
	for _, h := range result.Hosts {
		if !h.Alive {
			continue
		}
		var asset models.Asset
		_ = j.db.Where("engagement_id = ? AND ip = ?", engID, h.IP).First(&asset).Error
		fields := map[string]interface{}{}
		// Parse enum notes from OS field when present
		if strings.Contains(h.OS, "hostname=") || strings.Contains(h.OS, "host=") || strings.Contains(h.OS, "title=") || strings.Contains(h.OS, "tls") {
			for _, part := range strings.Split(h.OS, ";") {
				part = strings.TrimSpace(part)
				if strings.HasPrefix(part, "hostname=") || strings.HasPrefix(part, "host=") {
					fields["hostname"] = strings.TrimPrefix(strings.TrimPrefix(part, "hostname="), "host=")
				}
				if strings.HasPrefix(part, "title=") {
					fields["http_title"] = strings.TrimPrefix(part, "title=")
				}
				if strings.HasPrefix(part, "tls_cn=") || strings.HasPrefix(part, "tls=") {
					fields["tls_cn"] = strings.TrimPrefix(strings.TrimPrefix(part, "tls_cn="), "tls=")
				}
			}
		}
		if result.ScanType == models.ScanTypePathTrace && h.OS != "" {
			fields["traceroute"] = h.OS
		}
		if result.ScanType == models.ScanTypeOSFingerprint && h.OS != "" && !strings.Contains(h.OS, "=") {
			fields["os"] = h.OS
		}
		if len(fields) > 0 {
			_ = UpdateAssetEnum(j.db, engID, h.IP, fields)
			_ = j.db.Where("engagement_id = ? AND ip = ?", engID, h.IP).First(&asset).Error
		}

		var assetID *uint
		if asset.ID != 0 {
			assetID = &asset.ID
		}

		// Vuln findings from host
		for _, vf := range h.VulnFindings {
			f := models.Finding{
				EngagementID: engID,
				AssetID:      assetID,
				Port:         vf.Port,
				Severity:     vf.Severity,
				Status:       models.FindingOpen,
				Title:        vf.Title,
				Description:  vf.Description,
				CVE:          vf.CVE,
				Evidence:     vf.Evidence,
				Category:     "vuln",
			}
			_ = j.db.Create(&f).Error
		}
		// Also run rule pack for port scans / pipeline / enum
		if result.ScanType == models.ScanTypePortScan || result.ScanType == models.ScanTypePipeline || result.ScanType == models.ScanTypeEnum {
			for _, f := range MatchVulnRules(h) {
				f.EngagementID = engID
				f.AssetID = assetID
				_ = j.db.Create(&f).Error
			}
		}
	}
	if authFinding != nil {
		authFinding.EngagementID = engID
		var asset models.Asset
		if err := j.db.Where("engagement_id = ? AND ip = ?", engID, result.Target).First(&asset).Error; err == nil {
			authFinding.AssetID = &asset.ID
		}
		_ = j.db.Create(authFinding).Error
	}
}

func (j *JobManager) vulnFromExisting(ctx context.Context, newID, sourceID uint) (*models.ScanReport, error) {
	var source models.ScanReport
	if err := j.db.Preload("Hosts.OpenPorts").First(&source, sourceID).Error; err != nil {
		return nil, fmt.Errorf("source scan not found")
	}
	if err := ctx.Err(); err != nil {
		return nil, err
	}
	hosts := AnalyzeExistingHosts(source.Hosts)
	// Also attach Finding-compatible VulnFindings from rule pack
	for i := range hosts {
		findings := MatchVulnRules(hosts[i])
		hosts[i].VulnFindings = nil
		for _, f := range findings {
			hosts[i].VulnFindings = append(hosts[i].VulnFindings, models.VulnFinding{
				Port: f.Port, Severity: f.Severity, Title: f.Title,
				Description: f.Description, CVE: f.CVE, Evidence: f.Evidence,
			})
		}
		hosts[i].ID = 0
		hosts[i].ScanID = newID
		for k := range hosts[i].OpenPorts {
			hosts[i].OpenPorts[k].ID = 0
			hosts[i].OpenPorts[k].HostResultID = 0
		}
		for k := range hosts[i].VulnFindings {
			hosts[i].VulnFindings[k].ID = 0
			hosts[i].VulnFindings[k].HostResultID = 0
		}
	}
	return &models.ScanReport{Hosts: hosts, Status: models.StatusDone}, nil
}
