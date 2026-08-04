package services

import (
	"context"
	"fmt"
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
	MaxHosts        int
	MaxPorts        int
	DefaultHostConc int
	DefaultPortConc int
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
	SourceScanID    uint // optional: analyze existing scan for vuln
}

func (j *JobManager) Start(req StartRequest) (*models.ScanReport, error) {
	if req.HostConcurrency <= 0 {
		req.HostConcurrency = j.cfg.DefaultHostConc
	}
	if req.PortConcurrency <= 0 {
		req.PortConcurrency = j.cfg.DefaultPortConc
	}

	report := models.ScanReport{
		Generated:    time.Now(),
		ScanType:     req.ScanType,
		Status:       models.StatusPending,
		Target:       req.Target,
		PortsScanned: req.Ports,
		Notes:        req.Notes,
		Progress:     0,
	}
	switch req.ScanType {
	case models.ScanTypeHostDiscovery:
		report.PortsScanned = "Host Discovery"
	case models.ScanTypeOSFingerprint:
		report.PortsScanned = "OS Fingerprinting"
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
		}
		_ = j.db.Model(&models.ScanReport{}).Where("id = ?", id).Update("progress", pct).Error
	}

	var result *models.ScanReport
	var err error

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
	_ = j.db.Model(&models.ScanReport{}).Where("id = ?", id).Updates(map[string]interface{}{
		"status":   models.StatusDone,
		"progress": 100,
	}).Error
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
	for i := range hosts {
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
	return &models.ScanReport{
		Hosts:  hosts,
		Status: models.StatusDone,
	}, nil
}
