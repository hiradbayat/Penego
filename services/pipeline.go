package services

import (
	"context"
	"fmt"
	"time"

	"penego/models"
)

// RunAssessmentPipeline: discovery → top TCP ports → enum → vuln match.
func RunAssessmentPipeline(ctx context.Context, opts ScanOptions, onProgress func(done, total int)) (*models.ScanReport, error) {
	normalizeOpts(&opts)
	if opts.Ports == "" {
		opts.Ports = "21,22,23,25,53,80,110,139,443,445,993,995,3306,3389,5432,8080,8443"
	}

	stages := 4
	reportProgress := func(stage, stageDone, stageTotal int) {
		if onProgress == nil {
			return
		}
		// Map stage progress into overall 0-100
		base := (stage - 1) * 100 / stages
		span := 100 / stages
		pct := base
		if stageTotal > 0 {
			pct = base + stageDone*span/stageTotal
		}
		onProgress(pct, 100)
	}

	// Stage 1: host discovery
	discOpts := opts
	disc, err := RunHostDiscovery(ctx, discOpts, func(d, t int) { reportProgress(1, d, t) })
	if err != nil {
		return nil, fmt.Errorf("discovery: %w", err)
	}
	aliveIPs := make([]string, 0)
	for _, h := range disc.Hosts {
		if h.Alive {
			aliveIPs = append(aliveIPs, h.IP)
		}
	}
	if len(aliveIPs) == 0 {
		// fall back to scanning original target list
		aliveIPs, err = ResolveTargets(opts.Target, opts.MaxHosts)
		if err != nil {
			return nil, err
		}
	}

	// Stage 2: port scan alive hosts (as synthetic CIDR-like sequential)
	portHosts := make([]models.HostResult, 0)
	timeout := time.Duration(opts.TimeoutMs) * time.Millisecond
	ports, err := ParsePorts(opts.Ports)
	if err != nil {
		return nil, err
	}
	for i, ip := range aliveIPs {
		if ctx.Err() != nil {
			return nil, ctx.Err()
		}
		hr := ScanHost(ip, ports, timeout, opts.PortConcurrency, true)
		portHosts = append(portHosts, hr)
		reportProgress(2, i+1, len(aliveIPs))
	}

	// Stage 3: enum
	for i := range portHosts {
		if ctx.Err() != nil {
			return nil, ctx.Err()
		}
		if !portHosts[i].Alive {
			reportProgress(3, i+1, len(portHosts))
			continue
		}
		openPorts := make([]int, 0)
		for _, p := range portHosts[i].OpenPorts {
			openPorts = append(openPorts, p.Port)
		}
		er := EnumerateHost(ctx, portHosts[i].IP, openPorts, 3*time.Second)
		parts := []string{}
		if er.Hostname != "" {
			parts = append(parts, "host="+er.Hostname)
		}
		if er.HTTPTitle != "" {
			parts = append(parts, "title="+er.HTTPTitle)
		}
		if er.TLSCN != "" {
			parts = append(parts, "tls="+er.TLSCN)
		}
		if len(parts) > 0 {
			if portHosts[i].OS != "" {
				portHosts[i].OS = portHosts[i].OS + "; "
			}
			portHosts[i].OS = portHosts[i].OS + joinStrings(parts, ", ")
		}
		// TLS findings attached later via Finding model at job layer
		reportProgress(3, i+1, len(portHosts))
	}

	// Stage 4: vuln match → VulnFindings on hosts for persistence compatibility
	for i := range portHosts {
		findings := MatchVulnRules(portHosts[i])
		for _, f := range findings {
			portHosts[i].VulnFindings = append(portHosts[i].VulnFindings, models.VulnFinding{
				Port:        f.Port,
				Severity:    f.Severity,
				Title:       f.Title,
				Description: f.Description,
				CVE:         f.CVE,
				Evidence:    f.Evidence,
			})
		}
		reportProgress(4, i+1, len(portHosts))
	}

	return &models.ScanReport{
		Generated:    time.Now(),
		ScanType:     models.ScanTypePipeline,
		Status:       models.StatusDone,
		Target:       opts.Target,
		PortsScanned: opts.Ports,
		Notes:        "Assessment pipeline: discovery → ports → enum → vuln",
		Progress:     100,
		Hosts:        portHosts,
	}, nil
}

func joinStrings(parts []string, sep string) string {
	if len(parts) == 0 {
		return ""
	}
	out := parts[0]
	for i := 1; i < len(parts); i++ {
		out += sep + parts[i]
	}
	return out
}
