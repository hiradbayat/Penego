package handlers

import (
	"net/http"
	"strings"

	"github.com/gin-gonic/gin"
	"gorm.io/gorm"
	"penego/middlewares"
	"penego/models"
	"penego/services"
)

type EngagementHandler struct {
	DB *gorm.DB
}

func NewEngagementHandler(db *gorm.DB) *EngagementHandler {
	return &EngagementHandler{DB: db}
}

type engagementBody struct {
	Name        string `json:"name"`
	Description string `json:"description"`
	ScopeCIDRs  string `json:"scope_cidrs"`
	Notes       string `json:"notes"`
	Status      string `json:"status"`
}

func (h *EngagementHandler) List(c *gin.Context) {
	var items []models.Engagement
	q := h.DB.Order("id desc")
	if s := c.Query("status"); s != "" {
		q = q.Where("status = ?", s)
	}
	if err := q.Find(&items).Error; err != nil {
		c.JSON(http.StatusInternalServerError, gin.H{"error": err.Error()})
		return
	}
	c.JSON(http.StatusOK, gin.H{"items": items})
}

func (h *EngagementHandler) Create(c *gin.Context) {
	var req engagementBody
	if err := c.ShouldBindJSON(&req); err != nil {
		c.JSON(http.StatusBadRequest, gin.H{"error": err.Error()})
		return
	}
	e, err := services.CreateEngagement(h.DB, req.Name, req.Description, req.ScopeCIDRs, req.Notes, middlewares.CurrentUser(c))
	if err != nil {
		c.JSON(http.StatusBadRequest, gin.H{"error": err.Error()})
		return
	}
	services.WriteAudit(h.DB, middlewares.CurrentUser(c), "create_engagement", e.Name, "", c.ClientIP())
	c.JSON(http.StatusCreated, e)
}

func (h *EngagementHandler) Get(c *gin.Context) {
	var e models.Engagement
	if err := h.DB.First(&e, c.Param("id")).Error; err != nil {
		c.JSON(http.StatusNotFound, gin.H{"error": "engagement not found"})
		return
	}
	var assets []models.Asset
	_ = h.DB.Where("engagement_id = ?", e.ID).Order("ip").Find(&assets).Error
	var findings []models.Finding
	_ = h.DB.Where("engagement_id = ?", e.ID).Order("severity, id desc").Limit(200).Find(&findings).Error
	var scans []models.ScanReport
	_ = h.DB.Where("engagement_id = ?", e.ID).Order("id desc").Limit(50).Find(&scans).Error
	c.JSON(http.StatusOK, gin.H{
		"engagement": e,
		"assets":     assets,
		"findings":   findings,
		"scans":      models.ToScanReportJSONList(scans),
	})
}

func (h *EngagementHandler) Update(c *gin.Context) {
	var e models.Engagement
	if err := h.DB.First(&e, c.Param("id")).Error; err != nil {
		c.JSON(http.StatusNotFound, gin.H{"error": "engagement not found"})
		return
	}
	var req engagementBody
	if err := c.ShouldBindJSON(&req); err != nil {
		c.JSON(http.StatusBadRequest, gin.H{"error": err.Error()})
		return
	}
	updates := map[string]interface{}{}
	if req.Name != "" {
		updates["name"] = req.Name
	}
	if req.Description != "" {
		updates["description"] = req.Description
	}
	if req.Notes != "" {
		updates["notes"] = req.Notes
	}
	if req.ScopeCIDRs != "" {
		if err := services.ValidateScopeList(req.ScopeCIDRs); err != nil {
			c.JSON(http.StatusBadRequest, gin.H{"error": err.Error()})
			return
		}
		updates["scope_cidrs"] = req.ScopeCIDRs
	}
	if req.Status != "" {
		updates["status"] = req.Status
	}
	if err := h.DB.Model(&e).Updates(updates).Error; err != nil {
		c.JSON(http.StatusInternalServerError, gin.H{"error": err.Error()})
		return
	}
	_ = h.DB.First(&e, e.ID)
	c.JSON(http.StatusOK, e)
}

func (h *EngagementHandler) Close(c *gin.Context) {
	res := h.DB.Model(&models.Engagement{}).Where("id = ?", c.Param("id")).Update("status", models.EngagementClosed)
	if res.Error != nil || res.RowsAffected == 0 {
		c.JSON(http.StatusNotFound, gin.H{"error": "engagement not found"})
		return
	}
	services.WriteAudit(h.DB, middlewares.CurrentUser(c), "close_engagement", c.Param("id"), "", c.ClientIP())
	c.JSON(http.StatusOK, gin.H{"message": "closed"})
}

func (h *EngagementHandler) ListFindings(c *gin.Context) {
	q := h.DB.Model(&models.Finding{}).Where("engagement_id = ?", c.Param("id"))
	if s := c.Query("severity"); s != "" {
		q = q.Where("severity = ?", s)
	}
	if s := c.Query("status"); s != "" {
		q = q.Where("status = ?", s)
	}
	if s := strings.TrimSpace(c.Query("q")); s != "" {
		like := "%" + s + "%"
		q = q.Where("title LIKE ? OR cve LIKE ? OR evidence LIKE ?", like, like, like)
	}
	var items []models.Finding
	if err := q.Order("id desc").Limit(500).Find(&items).Error; err != nil {
		c.JSON(http.StatusInternalServerError, gin.H{"error": err.Error()})
		return
	}
	c.JSON(http.StatusOK, gin.H{"items": items})
}

func (h *EngagementHandler) UpdateFinding(c *gin.Context) {
	var f models.Finding
	if err := h.DB.Where("engagement_id = ? AND id = ?", c.Param("id"), c.Param("fid")).First(&f).Error; err != nil {
		c.JSON(http.StatusNotFound, gin.H{"error": "finding not found"})
		return
	}
	var body struct {
		Status string `json:"status"`
	}
	if err := c.ShouldBindJSON(&body); err != nil {
		c.JSON(http.StatusBadRequest, gin.H{"error": err.Error()})
		return
	}
	if body.Status != models.FindingOpen && body.Status != models.FindingFixed && body.Status != models.FindingAccepted {
		c.JSON(http.StatusBadRequest, gin.H{"error": "invalid status"})
		return
	}
	f.Status = body.Status
	if err := h.DB.Save(&f).Error; err != nil {
		c.JSON(http.StatusInternalServerError, gin.H{"error": err.Error()})
		return
	}
	c.JSON(http.StatusOK, f)
}

func (h *EngagementHandler) ExportHTML(c *gin.Context) {
	var e models.Engagement
	if err := h.DB.First(&e, c.Param("id")).Error; err != nil {
		c.JSON(http.StatusNotFound, gin.H{"error": "not found"})
		return
	}
	var assets []models.Asset
	_ = h.DB.Where("engagement_id = ?", e.ID).Find(&assets).Error
	var findings []models.Finding
	_ = h.DB.Where("engagement_id = ?", e.ID).Order("severity").Find(&findings).Error
	var scans []models.ScanReport
	_ = h.DB.Where("engagement_id = ?", e.ID).Order("id").Find(&scans).Error
	html, err := services.RenderEngagementReport(e, assets, findings, scans)
	if err != nil {
		c.JSON(http.StatusInternalServerError, gin.H{"error": err.Error()})
		return
	}
	c.Header("Content-Disposition", "attachment; filename="+services.EngagementReportFilename(e))
	c.Data(http.StatusOK, "text/html; charset=utf-8", html)
}

func (h *EngagementHandler) ListAssets(c *gin.Context) {
	var assets []models.Asset
	if err := h.DB.Where("engagement_id = ?", c.Param("id")).Order("ip").Find(&assets).Error; err != nil {
		c.JSON(http.StatusInternalServerError, gin.H{"error": err.Error()})
		return
	}
	c.JSON(http.StatusOK, gin.H{"items": assets})
}
