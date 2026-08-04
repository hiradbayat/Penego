package handlers

import (
	"net/http"
	"strconv"
	"strings"

	"github.com/gin-gonic/gin"
	"gorm.io/gorm"
	"penego/config"
	"penego/middlewares"
	"penego/models"
	"penego/services"
)

type ScanHandler struct {
	DB     *gorm.DB
	Jobs   *services.JobManager
	Config *config.Config
}

func NewScanHandler(db *gorm.DB, jobs *services.JobManager, cfg *config.Config) *ScanHandler {
	return &ScanHandler{DB: db, Jobs: jobs, Config: cfg}
}

type scanStartBody struct {
	Target          string `json:"target"`
	Ports           string `json:"ports"`
	Concurrency     int    `json:"concurrency"`
	HostConcurrency int    `json:"host_concurrency"`
	PortConcurrency int    `json:"port_concurrency"`
	TimeoutMs       int    `json:"timeout_ms"`
	GrabBanner      bool   `json:"grab_banner"`
	SourceScanID    uint   `json:"source_scan_id"`
}

func (h *ScanHandler) startJob(c *gin.Context, scanType string, portsRequired bool) {
	var req scanStartBody
	if err := c.ShouldBindJSON(&req); err != nil {
		c.JSON(http.StatusBadRequest, gin.H{"error": err.Error()})
		return
	}
	if portsRequired && req.Ports == "" {
		c.JSON(http.StatusBadRequest, gin.H{"error": "ports is required"})
		return
	}
	if req.SourceScanID > 0 && scanType == models.ScanTypeVulnScan {
		if req.Target == "" {
			req.Target = "from-existing-scan"
		}
	} else if err := services.ValidateTarget(req.Target); err != nil {
		c.JSON(http.StatusBadRequest, gin.H{"error": err.Error()})
		return
	}

	hostConc := req.HostConcurrency
	portConc := req.PortConcurrency
	if hostConc == 0 {
		hostConc = req.Concurrency
	}
	if portConc == 0 {
		portConc = req.Concurrency
	}

	report, err := h.Jobs.Start(services.StartRequest{
		ScanType:        scanType,
		Target:          req.Target,
		Ports:           req.Ports,
		HostConcurrency: hostConc,
		PortConcurrency: portConc,
		TimeoutMs:       req.TimeoutMs,
		GrabBanner:      req.GrabBanner,
		Notes:           "Scan initiated via web interface",
		SourceScanID:    req.SourceScanID,
	})
	if err != nil {
		c.JSON(http.StatusBadRequest, gin.H{"error": err.Error()})
		return
	}

	services.WriteAudit(h.DB, middlewares.CurrentUser(c), "start_scan", req.Target, scanType, c.ClientIP())

	c.JSON(http.StatusAccepted, gin.H{
		"message":   "Scan started",
		"scan_id":   report.ID,
		"status":    report.Status,
		"scan_type": report.ScanType,
	})
}

func (h *ScanHandler) ScanNetwork(c *gin.Context) {
	h.startJob(c, models.ScanTypePortScan, true)
}

func (h *ScanHandler) HostDiscovery(c *gin.Context) {
	h.startJob(c, models.ScanTypeHostDiscovery, false)
}

func (h *ScanHandler) OSFingerprint(c *gin.Context) {
	h.startJob(c, models.ScanTypeOSFingerprint, false)
}

func (h *ScanHandler) VulnScan(c *gin.Context) {
	h.startJob(c, models.ScanTypeVulnScan, false)
}

func (h *ScanHandler) CancelScan(c *gin.Context) {
	id, err := strconv.ParseUint(c.Param("id"), 10, 64)
	if err != nil {
		c.JSON(http.StatusBadRequest, gin.H{"error": "invalid id"})
		return
	}
	if err := h.Jobs.Cancel(uint(id)); err != nil {
		c.JSON(http.StatusBadRequest, gin.H{"error": err.Error()})
		return
	}
	services.WriteAudit(h.DB, middlewares.CurrentUser(c), "cancel_scan", c.Param("id"), "", c.ClientIP())
	c.JSON(http.StatusOK, gin.H{"message": "cancel requested"})
}

func (h *ScanHandler) GetScanResults(c *gin.Context) {
	scanType := c.Query("type")
	status := c.Query("status")
	search := strings.TrimSpace(c.Query("q"))
	page, _ := strconv.Atoi(c.DefaultQuery("page", "1"))
	limit, _ := strconv.Atoi(c.DefaultQuery("limit", "10"))
	if page < 1 {
		page = 1
	}
	if limit < 1 || limit > 100 {
		limit = 10
	}

	q := h.DB.Model(&models.ScanReport{})
	if scanType != "" {
		q = q.Where("scan_type = ?", scanType)
	}
	if status != "" {
		q = q.Where("status = ?", status)
	}
	if search != "" {
		like := "%" + search + "%"
		q = q.Where(
			"CAST(id AS CHAR) LIKE ? OR target LIKE ? OR ports_scanned LIKE ? OR notes LIKE ? OR scan_type LIKE ?",
			like, like, like, like, like,
		)
	}

	var total int64
	if err := q.Count(&total).Error; err != nil {
		c.JSON(http.StatusInternalServerError, gin.H{"error": err.Error()})
		return
	}

	var scans []models.ScanReport
	offset := (page - 1) * limit
	if err := q.Preload("Hosts.OpenPorts").Preload("Hosts.VulnFindings").
		Order("id desc").Offset(offset).Limit(limit).Find(&scans).Error; err != nil {
		c.JSON(http.StatusInternalServerError, gin.H{"error": err.Error()})
		return
	}

	c.JSON(http.StatusOK, gin.H{
		"items":  models.ToScanReportJSONList(scans),
		"page":   page,
		"limit":  limit,
		"total":  total,
		"q":      search,
		"status": status,
		"type":   scanType,
	})
}

func (h *ScanHandler) GetScanByID(c *gin.Context) {
	var scan models.ScanReport
	if err := h.DB.Preload("Hosts.OpenPorts").Preload("Hosts.VulnFindings").
		First(&scan, c.Param("id")).Error; err != nil {
		c.JSON(http.StatusNotFound, gin.H{"error": "Scan not found"})
		return
	}
	c.JSON(http.StatusOK, models.ToScanReportJSON(scan))
}

func (h *ScanHandler) DeleteScan(c *gin.Context) {
	id := c.Param("id")
	var scan models.ScanReport
	if err := h.DB.First(&scan, id).Error; err != nil {
		c.JSON(http.StatusNotFound, gin.H{"error": "Scan not found"})
		return
	}
	var hosts []models.HostResult
	_ = h.DB.Where("scan_id = ?", scan.ID).Find(&hosts).Error
	for _, host := range hosts {
		_ = h.DB.Where("host_result_id = ?", host.ID).Delete(&models.PortInfo{}).Error
		_ = h.DB.Where("host_result_id = ?", host.ID).Delete(&models.VulnFinding{}).Error
	}
	_ = h.DB.Where("scan_id = ?", scan.ID).Delete(&models.HostResult{}).Error
	if err := h.DB.Delete(&scan).Error; err != nil {
		c.JSON(http.StatusInternalServerError, gin.H{"error": err.Error()})
		return
	}
	services.WriteAudit(h.DB, middlewares.CurrentUser(c), "delete_scan", id, "", c.ClientIP())
	c.JSON(http.StatusOK, gin.H{"message": "deleted"})
}

func (h *ScanHandler) ExportScanJSON(c *gin.Context) {
	var scan models.ScanReport
	if err := h.DB.Preload("Hosts.OpenPorts").Preload("Hosts.VulnFindings").
		First(&scan, c.Param("id")).Error; err != nil {
		c.JSON(http.StatusNotFound, gin.H{"error": "Scan not found"})
		return
	}
	c.Header("Content-Disposition", "attachment; filename=penego-scan-"+c.Param("id")+".json")
	c.JSON(http.StatusOK, models.ToScanReportJSON(scan))
}

func (h *ScanHandler) ExportScanHTML(c *gin.Context) {
	var scan models.ScanReport
	if err := h.DB.Preload("Hosts.OpenPorts").Preload("Hosts.VulnFindings").
		First(&scan, c.Param("id")).Error; err != nil {
		c.JSON(http.StatusNotFound, gin.H{"error": "Scan not found"})
		return
	}
	html, err := services.RenderHTMLReport(scan)
	if err != nil {
		c.JSON(http.StatusInternalServerError, gin.H{"error": err.Error()})
		return
	}
	c.Header("Content-Disposition", "attachment; filename="+services.ReportFilename(scan))
	c.Data(http.StatusOK, "text/html; charset=utf-8", html)
}

func (h *ScanHandler) NetworkMap(c *gin.Context) {
	var scans []models.ScanReport
	q := h.DB.Preload("Hosts.OpenPorts").Where("status = ?", models.StatusDone)
	if t := c.Query("type"); t != "" {
		q = q.Where("scan_type = ?", t)
	}
	if err := q.Order("id desc").Limit(50).Find(&scans).Error; err != nil {
		c.JSON(http.StatusInternalServerError, gin.H{"error": err.Error()})
		return
	}
	c.JSON(http.StatusOK, services.BuildNetworkMap(scans))
}
