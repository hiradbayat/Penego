package handlers

import (
	"bufio"
	"fmt"
	"github.com/gin-gonic/gin"
	"gorm.io/gorm"
	"net"
	"net/http"
	"penego/models"
	"sort"
	"strconv"
	"strings"
	"sync"
	"time"
)

type ScanRequest struct {
	Target      string `json:"target" binding:"required"`
	Ports       string `json:"ports" binding:"required"`
	Concurrency int    `json:"concurrency"`
	TimeoutMs   int    `json:"timeout_ms"`
	GrabBanner  bool   `json:"grab_banner"`
}

type ScanHandler struct {
	DB *gorm.DB
}

func NewScanHandler(db *gorm.DB) *ScanHandler {
	return &ScanHandler{DB: db}
}

// Small fingerprints for non-exploitative checks
var fingerprints = map[string]string{
	"OpenSSH":    "SSH server",
	"Apache":     "Apache HTTP Server",
	"nginx":      "nginx HTTP Server",
	"MySQL":      "MySQL service",
	"PostgreSQL": "PostgreSQL service",
}

func (h *ScanHandler) ParsePorts(s string) ([]int, error) {
	out := make(map[int]struct{})
	parts := strings.Split(s, ",")
	for _, p := range parts {
		p = strings.TrimSpace(p)
		if p == "" {
			continue
		}
		if strings.Contains(p, "-") {
			r := strings.SplitN(p, "-", 2)
			if len(r) != 2 {
				return nil, fmt.Errorf("bad range: %s", p)
			}
			lo, err := strconv.Atoi(strings.TrimSpace(r[0]))
			if err != nil {
				return nil, err
			}
			hi, err := strconv.Atoi(strings.TrimSpace(r[1]))
			if err != nil {
				return nil, err
			}
			if lo > hi {
				lo, hi = hi, lo
			}
			for i := lo; i <= hi; i++ {
				out[i] = struct{}{}
			}
		} else {
			v, err := strconv.Atoi(p)
			if err != nil {
				return nil, err
			}
			out[v] = struct{}{}
		}
	}
	ports := make([]int, 0, len(out))
	for k := range out {
		ports = append(ports, k)
	}
	sort.Ints(ports)
	return ports, nil
}

func (h *ScanHandler) HostsFromCIDR(cidr string) ([]string, error) {
	ip, ipnet, err := net.ParseCIDR(cidr)
	if err != nil {
		return nil, err
	}
	var ips []string
	for ip := ip.Mask(ipnet.Mask); ipnet.Contains(ip); h.incIP(ip) {
		ips = append(ips, ip.String())
	}
	if len(ips) > 2 {
		return ips[1 : len(ips)-1], nil
	}
	return ips, nil
}

func (h *ScanHandler) incIP(ip net.IP) {
	for j := len(ip) - 1; j >= 0; j-- {
		ip[j]++
		if ip[j] != 0 {
			break
		}
	}
}

func (h *ScanHandler) ProbeTCP(ip string, port int, timeout time.Duration, grabBanner bool) (models.PortInfo, error) {
	pi := models.PortInfo{Port: port, Open: false}
	addr := net.JoinHostPort(ip, strconv.Itoa(port))
	conn, err := net.DialTimeout("tcp", addr, timeout)
	if err != nil {
		return pi, nil
	}
	defer conn.Close()
	pi.Open = true

	if grabBanner {
		conn.SetReadDeadline(time.Now().Add(2 * time.Second))
		r := bufio.NewReader(conn)
		b, _ := r.Peek(512)
		pi.Banner = strings.TrimSpace(string(b))

		for k, v := range fingerprints {
			if strings.Contains(strings.ToLower(pi.Banner), strings.ToLower(k)) {
				pi.Service = v
				break
			}
		}
	}
	return pi, nil
}

func (h *ScanHandler) ScanHost(ip string, ports []int, timeout time.Duration, concurrency int, grabBanner bool) models.HostResult {
	host := models.HostResult{IP: ip, Alive: false}
	var wg sync.WaitGroup
	sem := make(chan struct{}, concurrency)
	resCh := make(chan models.PortInfo, len(ports))

	for _, p := range ports {
		wg.Add(1)
		sem <- struct{}{}
		go func(port int) {
			defer wg.Done()
			pi, _ := h.ProbeTCP(ip, port, timeout, grabBanner)
			if pi.Open {
				resCh <- pi
			}
			<-sem
		}(p)
	}

	wg.Wait()
	close(resCh)

	for pi := range resCh {
		host.OpenPorts = append(host.OpenPorts, pi)
	}

	if len(host.OpenPorts) > 0 {
		host.Alive = true
	}

	return host
}

func (h *ScanHandler) ScanNetwork(c *gin.Context) {
	var req ScanRequest
	if err := c.ShouldBindJSON(&req); err != nil {
		c.JSON(http.StatusBadRequest, gin.H{"error": err.Error()})
		return
	}

	// Set defaults
	if req.Concurrency == 0 {
		req.Concurrency = 200
	}
	if req.TimeoutMs == 0 {
		req.TimeoutMs = 1000
	}

	ports, err := h.ParsePorts(req.Ports)
	if err != nil {
		c.JSON(http.StatusBadRequest, gin.H{"error": "Invalid ports: " + err.Error()})
		return
	}

	timeout := time.Duration(req.TimeoutMs) * time.Millisecond

	var targets []string
	if strings.Contains(req.Target, "/") {
		// CIDR
		ips, err := h.HostsFromCIDR(req.Target)
		if err != nil {
			c.JSON(http.StatusBadRequest, gin.H{"error": "Invalid CIDR: " + err.Error()})
			return
		}
		targets = append(targets, ips...)
	} else {
		// Single IP
		targets = append(targets, req.Target)
	}

	// Create scan report
	scanReport := models.ScanReport{
		Generated:    time.Now(),
		Target:       req.Target,
		PortsScanned: req.Ports,
		Notes:        "Scan initiated via web interface",
	}

	semHosts := make(chan struct{}, req.Concurrency)
	var wg sync.WaitGroup
	resLock := sync.Mutex{}

	for _, ip := range targets {
		wg.Add(1)
		semHosts <- struct{}{}
		go func(ip string) {
			defer wg.Done()
			defer func() { <-semHosts }()

			hostResult := h.ScanHost(ip, ports, timeout, req.Concurrency, req.GrabBanner)

			resLock.Lock()
			if hostResult.Alive {
				scanReport.TrueTargets = append(scanReport.TrueTargets, hostResult)
			} else {
				scanReport.FalseTargets = append(scanReport.FalseTargets, hostResult)
			}
			resLock.Unlock()
		}(ip)
	}
	wg.Wait()

	// Sort results by IP
	sort.Slice(scanReport.TrueTargets, func(i, j int) bool {
		return scanReport.TrueTargets[i].IP < scanReport.TrueTargets[j].IP
	})
	sort.Slice(scanReport.FalseTargets, func(i, j int) bool {
		return scanReport.FalseTargets[i].IP < scanReport.FalseTargets[j].IP
	})

	// Save to database
	if err := h.DB.Create(&scanReport).Error; err != nil {
		c.JSON(http.StatusInternalServerError, gin.H{"error": "Failed to save scan results: " + err.Error()})
		return
	}

	c.JSON(http.StatusOK, gin.H{
		"message":     "Scan completed successfully",
		"scan_id":     scanReport.ID,
		"alive_hosts": len(scanReport.TrueTargets),
		"dead_hosts":  len(scanReport.FalseTargets),
		"generated":   scanReport.Generated,
	})
}

func (h *ScanHandler) GetScanResults(c *gin.Context) {
	var scans []models.ScanReport
	if err := h.DB.Preload("TrueTargets.OpenPorts").Preload("FalseTargets").Find(&scans).Error; err != nil {
		c.JSON(http.StatusInternalServerError, gin.H{"error": "Failed to fetch scan results: " + err.Error()})
		return
	}

	c.JSON(http.StatusOK, scans)
}

func (h *ScanHandler) GetScanByID(c *gin.Context) {
	id := c.Param("id")
	var scan models.ScanReport
	if err := h.DB.Preload("TrueTargets.OpenPorts").Preload("FalseTargets").First(&scan, id).Error; err != nil {
		c.JSON(http.StatusNotFound, gin.H{"error": "Scan not found"})
		return
	}

	c.JSON(http.StatusOK, scan)
}

func (h *ScanHandler) ServeHTML(c *gin.Context) {
	c.HTML(http.StatusOK, "index.html", gin.H{
		"title": "Network Scanner",
	})
}
