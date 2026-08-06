package services

import (
	"context"
	"crypto/tls"
	"fmt"
	"io"
	"net"
	"net/http"
	"regexp"
	"strings"
	"time"

	"penego/models"
)

var titleRE = regexp.MustCompile(`(?is)<title[^>]*>([^<]*)</title>`)

type EnumResult struct {
	IP         string
	Hostname   string
	HTTPTitle  string
	HTTPServer string
	HTTPStatus int
	TLSCN      string
	TLSSANs    string
	TLSExpiry  string
	SMBName    string
	Notes      string
}

func ReverseDNS(ip string) string {
	names, err := net.LookupAddr(ip)
	if err != nil || len(names) == 0 {
		return ""
	}
	return strings.TrimSuffix(names[0], ".")
}

func ProbeHTTP(ip string, port int, timeout time.Duration) (title, server string, status int) {
	client := &http.Client{
		Timeout: timeout,
		CheckRedirect: func(req *http.Request, via []*http.Request) error {
			if len(via) >= 2 {
				return http.ErrUseLastResponse
			}
			return nil
		},
	}
	schemes := []string{"http"}
	if port == 443 || port == 8443 {
		schemes = []string{"https", "http"}
	}
	for _, scheme := range schemes {
		url := fmt.Sprintf("%s://%s:%d/", scheme, ip, port)
		req, err := http.NewRequest(http.MethodGet, url, nil)
		if err != nil {
			continue
		}
		req.Header.Set("User-Agent", "Penego-Assessment/1.0")
		resp, err := client.Do(req)
		if err != nil {
			continue
		}
		body, _ := io.ReadAll(io.LimitReader(resp.Body, 64*1024))
		_ = resp.Body.Close()
		status = resp.StatusCode
		server = resp.Header.Get("Server")
		if m := titleRE.FindSubmatch(body); len(m) > 1 {
			title = strings.TrimSpace(string(m[1]))
		}
		return
	}
	return
}

func ProbeTLS(ip string, port int, timeout time.Duration) (cn, sans, expiry string, findings []models.Finding) {
	dialer := &net.Dialer{Timeout: timeout}
	conn, err := tls.DialWithDialer(dialer, "tcp", net.JoinHostPort(ip, fmt.Sprintf("%d", port)), &tls.Config{
		InsecureSkipVerify: true,
		MinVersion:         tls.VersionTLS10,
	})
	if err != nil {
		return
	}
	defer conn.Close()
	state := conn.ConnectionState()
	if len(state.PeerCertificates) == 0 {
		return
	}
	cert := state.PeerCertificates[0]
	cn = cert.Subject.CommonName
	sans = strings.Join(cert.DNSNames, ", ")
	expiry = cert.NotAfter.Format(time.RFC3339)
	if time.Now().After(cert.NotAfter) {
		findings = append(findings, models.Finding{
			Severity:    models.SeverityHigh,
			Status:      models.FindingOpen,
			Title:       "Expired TLS certificate",
			Description: "The TLS certificate presented by the service has expired.",
			Evidence:    "CN=" + cn + " expired " + expiry,
			Remediation: "Renew the certificate and redeploy.",
			Category:    "tls",
			Port:        port,
		})
	} else if time.Until(cert.NotAfter) < 30*24*time.Hour {
		findings = append(findings, models.Finding{
			Severity:    models.SeverityMedium,
			Status:      models.FindingOpen,
			Title:       "TLS certificate expires within 30 days",
			Description: "Certificate nearing expiry may cause outages.",
			Evidence:    "CN=" + cn + " expires " + expiry,
			Remediation: "Plan certificate renewal before expiry.",
			Category:    "tls",
			Port:        port,
		})
	}
	if state.Version == tls.VersionTLS10 || state.Version == tls.VersionTLS11 {
		findings = append(findings, models.Finding{
			Severity:    models.SeverityMedium,
			Status:      models.FindingOpen,
			Title:       "Weak TLS protocol negotiated",
			Description: "TLS 1.0/1.1 is deprecated and should be disabled.",
			Evidence:    fmt.Sprintf("negotiated version 0x%x", state.Version),
			Remediation: "Disable TLS 1.0/1.1; require TLS 1.2+.",
			Category:    "tls",
			Port:        port,
		})
	}
	return
}

// ProbeSMBBanner attempts a raw TCP peek on 445 for negotiation-like banner bytes (read-only).
func ProbeSMBBanner(ip string, timeout time.Duration) string {
	conn, err := net.DialTimeout("tcp", net.JoinHostPort(ip, "445"), timeout)
	if err != nil {
		return ""
	}
	defer conn.Close()
	_ = conn.SetDeadline(time.Now().Add(timeout))
	buf := make([]byte, 256)
	n, _ := conn.Read(buf)
	if n == 0 {
		return "tcp/445 open (no banner)"
	}
	return fmt.Sprintf("tcp/445 responded %d bytes", n)
}

func EnumerateHost(ctx context.Context, ip string, ports []int, timeout time.Duration) EnumResult {
	res := EnumResult{IP: ip, Hostname: ReverseDNS(ip)}
	if ctx.Err() != nil {
		return res
	}
	portSet := map[int]bool{}
	for _, p := range ports {
		portSet[p] = true
	}
	// Always try common web/tls ports if list empty
	checkPorts := ports
	if len(checkPorts) == 0 {
		checkPorts = []int{80, 443, 8080, 8443, 445}
	}
	for _, p := range checkPorts {
		if ctx.Err() != nil {
			break
		}
		switch p {
		case 80, 8080, 8000:
			title, server, status := ProbeHTTP(ip, p, timeout)
			if status > 0 {
				res.HTTPStatus = status
				if title != "" {
					res.HTTPTitle = title
				}
				if server != "" {
					res.HTTPServer = server
				}
			}
		case 443, 8443:
			cn, sans, exp, _ := ProbeTLS(ip, p, timeout)
			if cn != "" {
				res.TLSCN = cn
				res.TLSSANs = sans
				res.TLSExpiry = exp
			}
			title, server, status := ProbeHTTP(ip, p, timeout)
			if status > 0 && res.HTTPTitle == "" {
				res.HTTPTitle = title
				res.HTTPServer = server
				res.HTTPStatus = status
			}
		case 445:
			res.SMBName = ProbeSMBBanner(ip, timeout)
		}
	}
	return res
}

func RunServiceEnum(ctx context.Context, opts ScanOptions, onProgress func(done, total int)) (*models.ScanReport, error) {
	normalizeOpts(&opts)
	if opts.Ports == "" {
		opts.Ports = "80,443,445,8080,8443"
	}
	ports, err := ParsePorts(opts.Ports)
	if err != nil {
		return nil, err
	}
	targets, err := ResolveTargets(opts.Target, opts.MaxHosts)
	if err != nil {
		return nil, err
	}
	timeout := time.Duration(opts.TimeoutMs) * time.Millisecond
	if timeout < time.Second {
		timeout = 3 * time.Second
	}

	report := &models.ScanReport{
		Generated:    time.Now(),
		ScanType:     models.ScanTypeEnum,
		Status:       models.StatusRunning,
		Target:       opts.Target,
		PortsScanned: opts.Ports,
		Notes:        opts.Notes,
	}

	hosts, err := runOverHosts(ctx, targets, opts.HostConcurrency, onProgress, func(ip string) models.HostResult {
		alive := IsHostAlive(ip, timeout)
		hr := models.HostResult{IP: ip, Alive: alive}
		if !alive {
			// still try TCP on web ports for firewalled ICMP
			pi := ProbeTCP(ip, 80, timeout, false)
			if pi.Open {
				alive = true
				hr.Alive = true
			}
		}
		if !hr.Alive {
			return hr
		}
		er := EnumerateHost(ctx, ip, ports, timeout)
		notes := []string{}
		if er.Hostname != "" {
			notes = append(notes, "hostname="+er.Hostname)
		}
		if er.HTTPTitle != "" {
			notes = append(notes, "title="+er.HTTPTitle)
		}
		if er.TLSCN != "" {
			notes = append(notes, "tls_cn="+er.TLSCN)
		}
		if er.SMBName != "" {
			notes = append(notes, "smb="+er.SMBName)
		}
		hr.OS = strings.Join(notes, "; ")
		for _, p := range ports {
			pi := ProbeTCP(ip, p, timeout, true)
			if pi.Open {
				hr.OpenPorts = append(hr.OpenPorts, pi)
			}
		}
		return hr
	})
	if err != nil {
		return nil, err
	}
	report.Hosts = hosts
	report.Status = models.StatusDone
	report.Progress = 100
	return report, nil
}

// DefaultUDPPorts common UDP services for assessment.
var DefaultUDPPorts = []int{53, 123, 161, 500, 514, 1900, 5353}

func ProbeUDP(ip string, port int, timeout time.Duration) bool {
	addr := net.JoinHostPort(ip, fmt.Sprintf("%d", port))
	conn, err := net.DialTimeout("udp", addr, timeout)
	if err != nil {
		return false
	}
	defer conn.Close()
	_ = conn.SetDeadline(time.Now().Add(timeout))
	_, _ = conn.Write([]byte("\x00"))
	buf := make([]byte, 64)
	_, err = conn.Read(buf)
	// Any response => open; timeout => filtered/closed (treat as not open)
	return err == nil
}

func RunUDPScan(ctx context.Context, opts ScanOptions, onProgress func(done, total int)) (*models.ScanReport, error) {
	normalizeOpts(&opts)
	ports := DefaultUDPPorts
	if opts.Ports != "" {
		parsed, err := ParsePorts(opts.Ports)
		if err != nil {
			return nil, err
		}
		ports = parsed
	}
	if opts.MaxPorts > 0 && len(ports) > opts.MaxPorts {
		return nil, fmt.Errorf("too many ports: %d (max %d)", len(ports), opts.MaxPorts)
	}
	targets, err := ResolveTargets(opts.Target, opts.MaxHosts)
	if err != nil {
		return nil, err
	}
	timeout := time.Duration(opts.TimeoutMs) * time.Millisecond
	if timeout < 500*time.Millisecond {
		timeout = 1500 * time.Millisecond
	}
	report := &models.ScanReport{
		Generated:    time.Now(),
		ScanType:     models.ScanTypeUDPScan,
		Status:       models.StatusRunning,
		Target:       opts.Target,
		PortsScanned: "udp:" + joinInts(ports),
		Notes:        opts.Notes,
	}
	hosts, err := runOverHosts(ctx, targets, opts.HostConcurrency, onProgress, func(ip string) models.HostResult {
		hr := models.HostResult{IP: ip, Alive: false}
		for _, p := range ports {
			if ctx.Err() != nil {
				break
			}
			if ProbeUDP(ip, p, timeout) {
				hr.Alive = true
				hr.OpenPorts = append(hr.OpenPorts, models.PortInfo{Port: p, Open: true, Service: "udp"})
			}
		}
		return hr
	})
	if err != nil {
		return nil, err
	}
	report.Hosts = hosts
	report.Status = models.StatusDone
	report.Progress = 100
	return report, nil
}

func joinInts(ports []int) string {
	parts := make([]string, len(ports))
	for i, p := range ports {
		parts[i] = fmt.Sprintf("%d", p)
	}
	return strings.Join(parts, ",")
}
