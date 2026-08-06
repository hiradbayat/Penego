package services

import (
	"context"
	"fmt"
	"net"
	"os/exec"
	"regexp"
	"runtime"
	"strconv"
	"strings"
	"time"

	"penego/models"
)

var hopRE = regexp.MustCompile(`(\d+\.\d+\.\d+\.\d+|([0-9a-fA-F:]+))`)

func RunTraceroute(ip string, timeout time.Duration) (string, error) {
	var cmd *exec.Cmd
	if runtime.GOOS == "windows" {
		cmd = exec.Command("tracert", "-d", "-h", "15", "-w", "1000", ip)
	} else {
		cmd = exec.Command("traceroute", "-n", "-m", "15", "-w", "1", ip)
	}
	out, err := cmd.CombinedOutput()
	text := strings.TrimSpace(string(out))
	if err != nil && text == "" {
		// fallback: simple TTL probe summary
		return simplePathProbe(ip, timeout), err
	}
	return text, nil
}

func simplePathProbe(ip string, timeout time.Duration) string {
	hops := []string{}
	for ttl := 1; ttl <= 8; ttl++ {
		conn, err := net.DialTimeout("tcp", net.JoinHostPort(ip, "80"), timeout)
		if err == nil {
			_ = conn.Close()
			hops = append(hops, fmt.Sprintf("%d %s (tcp/80 reachable)", ttl, ip))
			break
		}
		hops = append(hops, fmt.Sprintf("%d *", ttl))
	}
	return strings.Join(hops, "\n")
}

func RunPathTrace(ctx context.Context, opts ScanOptions, onProgress func(done, total int)) (*models.ScanReport, error) {
	normalizeOpts(&opts)
	targets, err := ResolveTargets(opts.Target, opts.MaxHosts)
	if err != nil {
		return nil, err
	}
	timeout := time.Duration(opts.TimeoutMs) * time.Millisecond
	if timeout < time.Second {
		timeout = 2 * time.Second
	}
	report := &models.ScanReport{
		Generated:    time.Now(),
		ScanType:     models.ScanTypePathTrace,
		Status:       models.StatusRunning,
		Target:       opts.Target,
		PortsScanned: "Traceroute",
		Notes:        opts.Notes,
	}
	// Limit concurrency for traceroute (heavy)
	conc := opts.HostConcurrency
	if conc > 10 {
		conc = 10
	}
	hosts, err := runOverHosts(ctx, targets, conc, onProgress, func(ip string) models.HostResult {
		hr := models.HostResult{IP: ip, Alive: IsHostAlive(ip, timeout)}
		path, _ := RunTraceroute(ip, timeout)
		hr.OS = summarizeHops(path)
		if path != "" {
			hr.Alive = true
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

func summarizeHops(path string) string {
	lines := strings.Split(path, "\n")
	hops := make([]string, 0)
	for _, line := range lines {
		m := hopRE.FindString(line)
		if m != "" && net.ParseIP(m) != nil {
			hops = append(hops, m)
		}
	}
	if len(hops) == 0 {
		if len(path) > 200 {
			return path[:200] + "…"
		}
		return path
	}
	if len(hops) > 12 {
		hops = hops[:12]
	}
	return "hops: " + strings.Join(hops, " -> ")
}

func ParseHopCount(summary string) int {
	if !strings.HasPrefix(summary, "hops:") {
		return 0
	}
	parts := strings.Split(summary, "->")
	return len(parts)
}

func HopTTLLabel(n int) string {
	return strconv.Itoa(n)
}
