package services

import (
	"context"
	"fmt"
	"net"
	"net/http"
	"strings"
	"time"

	"penego/models"
)

type AuthCheckRequest struct {
	Host     string
	Port     int
	Service  string // ssh, ftp, http_basic
	Username string
	Password string
	Timeout  time.Duration
}

type AuthCheckResult struct {
	Success bool
	Message string
	Finding models.Finding
}

func RunAuthCheck(req AuthCheckRequest) AuthCheckResult {
	if req.Timeout <= 0 {
		req.Timeout = 5 * time.Second
	}
	if req.Port == 0 {
		switch strings.ToLower(req.Service) {
		case "ssh":
			req.Port = 22
		case "ftp":
			req.Port = 21
		case "http_basic":
			req.Port = 80
		}
	}
	svc := strings.ToLower(req.Service)
	var ok bool
	var msg string
	switch svc {
	case "ssh":
		ok, msg = checkSSH(req)
	case "ftp":
		ok, msg = checkFTP(req)
	case "http_basic":
		ok, msg = checkHTTPBasic(req)
	default:
		return AuthCheckResult{Success: false, Message: "unsupported service: " + req.Service}
	}

	sev := models.SeverityInfo
	title := fmt.Sprintf("Auth check failed (%s)", svc)
	if ok {
		sev = models.SeverityHigh
		title = fmt.Sprintf("Valid %s credentials confirmed", svc)
	}
	return AuthCheckResult{
		Success: ok,
		Message: msg,
		Finding: models.Finding{
			Port:        req.Port,
			Severity:    sev,
			Status:      models.FindingOpen,
			Title:       title,
			Description: "Authorized single-credential verification against " + req.Host,
			Evidence:    fmt.Sprintf("service=%s user=%s result=%s", svc, req.Username, msg),
			Remediation: "Rotate credentials if unexpected; enforce key-based or MFA auth where possible.",
			Category:    "auth",
		},
	}
}

func checkSSH(req AuthCheckRequest) (bool, string) {
	// Lightweight TCP + banner check; full SSH auth needs golang.org/x/crypto/ssh.
	// Attempt real SSH when library available via build tag-free import.
	return checkSSHPassword(req)
}

func checkFTP(req AuthCheckRequest) (bool, string) {
	addr := net.JoinHostPort(req.Host, fmt.Sprintf("%d", req.Port))
	conn, err := net.DialTimeout("tcp", addr, req.Timeout)
	if err != nil {
		return false, "connection failed: " + err.Error()
	}
	defer conn.Close()
	_ = conn.SetDeadline(time.Now().Add(req.Timeout))
	buf := make([]byte, 1024)
	n, _ := conn.Read(buf)
	banner := string(buf[:n])
	if !strings.HasPrefix(banner, "220") {
		return false, "unexpected FTP banner"
	}
	fmt.Fprintf(conn, "USER %s\r\n", req.Username)
	n, _ = conn.Read(buf)
	fmt.Fprintf(conn, "PASS %s\r\n", req.Password)
	n, _ = conn.Read(buf)
	resp := string(buf[:n])
	if strings.Contains(resp, "230") {
		fmt.Fprintf(conn, "QUIT\r\n")
		return true, "FTP login accepted"
	}
	return false, "FTP login rejected"
}

func checkHTTPBasic(req AuthCheckRequest) (bool, string) {
	client := &http.Client{Timeout: req.Timeout}
	url := fmt.Sprintf("http://%s:%d/", req.Host, req.Port)
	httpReq, err := http.NewRequest(http.MethodGet, url, nil)
	if err != nil {
		return false, err.Error()
	}
	httpReq.SetBasicAuth(req.Username, req.Password)
	httpReq.Header.Set("User-Agent", "Penego-AuthCheck/1.0")
	resp, err := client.Do(httpReq)
	if err != nil {
		return false, "request failed: " + err.Error()
	}
	defer resp.Body.Close()
	if resp.StatusCode == 401 || resp.StatusCode == 403 {
		return false, fmt.Sprintf("HTTP %d", resp.StatusCode)
	}
	if resp.StatusCode >= 200 && resp.StatusCode < 400 {
		return true, fmt.Sprintf("HTTP %d (auth may be accepted or unauthenticated)", resp.StatusCode)
	}
	return false, fmt.Sprintf("HTTP %d", resp.StatusCode)
}

// RunAuthCheckJob wraps a single host auth check as a ScanReport for JobManager.
func RunAuthCheckJob(ctx context.Context, opts ScanOptions, username, password, service string, port int, onProgress func(done, total int)) (*models.ScanReport, error) {
	if err := ctx.Err(); err != nil {
		return nil, err
	}
	if onProgress != nil {
		onProgress(0, 1)
	}
	res := RunAuthCheck(AuthCheckRequest{
		Host:     opts.Target,
		Port:     port,
		Service:  service,
		Username: username,
		Password: password,
		Timeout:  time.Duration(opts.TimeoutMs) * time.Millisecond,
	})
	hr := models.HostResult{IP: opts.Target, Alive: true}
	if res.Success {
		hr.OS = "auth_ok:" + service
	} else {
		hr.OS = "auth_fail:" + service
	}
	report := &models.ScanReport{
		Generated:    time.Now(),
		ScanType:     models.ScanTypeAuthCheck,
		Status:       models.StatusDone,
		Target:       opts.Target,
		PortsScanned: fmt.Sprintf("%s/%d", service, port),
		Notes:        res.Message,
		Progress:     100,
		Hosts:        []models.HostResult{hr},
	}
	if onProgress != nil {
		onProgress(1, 1)
	}
	return report, nil
}
