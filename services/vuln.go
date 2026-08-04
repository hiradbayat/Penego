package services

import (
	"context"
	"fmt"
	"regexp"
	"strconv"
	"strings"
	"time"

	"penego/models"
)

type vulnRule struct {
	Name        string
	ServiceHint string
	BannerRE    *regexp.Regexp
	VersionRE   *regexp.Regexp
	MaxSafe     string // if parsed version < this, flag (simple major.minor)
	Severity    string
	CVE         string
	Title       string
	Description string
}

var vulnRules = []vulnRule{
	{
		Name:        "openssh",
		ServiceHint: "SSH",
		BannerRE:    regexp.MustCompile(`(?i)OpenSSH[_\s-]?(\d+\.\d+)`),
		Severity:    "medium",
		CVE:         "CVE-2024-6387",
		Title:       "OpenSSH version disclosed",
		Description: "OpenSSH banner exposes a version that should be reviewed against current advisories.",
	},
	{
		Name:        "apache",
		ServiceHint: "Apache",
		BannerRE:    regexp.MustCompile(`(?i)Apache[/\s](\d+\.\d+\.\d+)`),
		Severity:    "medium",
		CVE:         "",
		Title:       "Apache HTTP Server version disclosed",
		Description: "Apache version in banner may indicate outdated software; verify against vendor advisories.",
	},
	{
		Name:        "nginx",
		ServiceHint: "nginx",
		BannerRE:    regexp.MustCompile(`(?i)nginx[/\s](\d+\.\d+\.\d+)`),
		Severity:    "low",
		CVE:         "",
		Title:       "nginx version disclosed",
		Description: "nginx version exposed in banner; confirm it is patched.",
	},
	{
		Name:        "mysql",
		ServiceHint: "MySQL",
		BannerRE:    regexp.MustCompile(`(?i)(\d+\.\d+\.\d+).*mysql|mysql.*(\d+\.\d+\.\d+)`),
		Severity:    "medium",
		CVE:         "",
		Title:       "MySQL version disclosed",
		Description: "MySQL service banner exposes version information.",
	},
	{
		Name:        "outdated_openssh_7",
		ServiceHint: "SSH",
		BannerRE:    regexp.MustCompile(`(?i)OpenSSH[_\s-]?(\d+)\.(\d+)`),
		Severity:    "high",
		CVE:         "CVE-2018-15473",
		Title:       "Potentially outdated OpenSSH (< 8.0)",
		Description: "OpenSSH major version below 8.0 may lack modern security fixes.",
	},
}

func MatchVulns(host models.HostResult) []models.VulnFinding {
	findings := make([]models.VulnFinding, 0)
	for _, p := range host.OpenPorts {
		text := p.Banner + " " + p.Service
		for _, rule := range vulnRules {
			if rule.BannerRE == nil || !rule.BannerRE.MatchString(text) {
				continue
			}
			if rule.Name == "outdated_openssh_7" {
				m := rule.BannerRE.FindStringSubmatch(text)
				if len(m) >= 3 {
					maj, _ := strconv.Atoi(m[1])
					if maj >= 8 {
						continue
					}
				}
			}
			findings = append(findings, models.VulnFinding{
				Port:        p.Port,
				Severity:    rule.Severity,
				Title:       rule.Title,
				Description: rule.Description,
				CVE:         rule.CVE,
				Evidence:    strings.TrimSpace(p.Banner),
			})
		}
		if p.Banner == "" && p.Open {
			continue
		}
	}
	return findings
}

func RunVulnScan(ctx context.Context, opts ScanOptions, onProgress func(done, total int)) (*models.ScanReport, error) {
	normalizeOpts(&opts)
	if opts.Ports == "" {
		opts.Ports = "21,22,23,25,80,443,3306,5432,8080,8443"
	}
	ports, err := ParsePorts(opts.Ports)
	if err != nil {
		return nil, fmt.Errorf("invalid ports: %w", err)
	}
	if opts.MaxPorts > 0 && len(ports) > opts.MaxPorts {
		return nil, fmt.Errorf("too many ports: %d (max %d)", len(ports), opts.MaxPorts)
	}
	targets, err := ResolveTargets(opts.Target, opts.MaxHosts)
	if err != nil {
		return nil, err
	}
	timeout := time.Duration(opts.TimeoutMs) * time.Millisecond

	report := &models.ScanReport{
		Generated:    time.Now(),
		ScanType:     models.ScanTypeVulnScan,
		Status:       models.StatusRunning,
		Target:       opts.Target,
		PortsScanned: opts.Ports,
		Notes:        opts.Notes,
	}

	hosts, err := runOverHosts(ctx, targets, opts.HostConcurrency, onProgress, func(ip string) models.HostResult {
		hr := ScanHost(ip, ports, timeout, opts.PortConcurrency, true)
		if hr.Alive {
			hr.VulnFindings = MatchVulns(hr)
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

// AnalyzeExistingHosts runs vuln rules against already-scanned hosts (from a prior scan).
func AnalyzeExistingHosts(hosts []models.HostResult) []models.HostResult {
	out := make([]models.HostResult, len(hosts))
	copy(out, hosts)
	for i := range out {
		out[i].VulnFindings = MatchVulns(out[i])
	}
	return out
}
