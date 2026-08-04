package services

import (
	"context"
	"fmt"
	"sort"
	"sync"
	"sync/atomic"
	"time"

	"penego/models"
)

type ScanOptions struct {
	Target          string
	Ports           string
	HostConcurrency int
	PortConcurrency int
	TimeoutMs       int
	GrabBanner      bool
	MaxHosts        int
	MaxPorts        int
	ScanType        string
	Notes           string
}

func normalizeOpts(opts *ScanOptions) {
	if opts.HostConcurrency <= 0 {
		opts.HostConcurrency = 100
	}
	if opts.PortConcurrency <= 0 {
		opts.PortConcurrency = 100
	}
	if opts.TimeoutMs <= 0 {
		opts.TimeoutMs = 1000
	}
}

func RunPortScan(ctx context.Context, opts ScanOptions, onProgress func(done, total int)) (*models.ScanReport, error) {
	normalizeOpts(&opts)
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
		ScanType:     models.ScanTypePortScan,
		Status:       models.StatusRunning,
		Target:       opts.Target,
		PortsScanned: opts.Ports,
		Notes:        opts.Notes,
	}

	hosts, err := runOverHosts(ctx, targets, opts.HostConcurrency, onProgress, func(ip string) models.HostResult {
		return ScanHost(ip, ports, timeout, opts.PortConcurrency, opts.GrabBanner)
	})
	if err != nil {
		return nil, err
	}
	report.Hosts = hosts
	report.Status = models.StatusDone
	report.Progress = 100
	return report, nil
}

func RunHostDiscovery(ctx context.Context, opts ScanOptions, onProgress func(done, total int)) (*models.ScanReport, error) {
	normalizeOpts(&opts)
	targets, err := ResolveTargets(opts.Target, opts.MaxHosts)
	if err != nil {
		return nil, err
	}
	timeout := time.Duration(opts.TimeoutMs) * time.Millisecond
	report := &models.ScanReport{
		Generated:    time.Now(),
		ScanType:     models.ScanTypeHostDiscovery,
		Status:       models.StatusRunning,
		Target:       opts.Target,
		PortsScanned: "Host Discovery",
		Notes:        opts.Notes,
	}

	hosts, err := runOverHosts(ctx, targets, opts.HostConcurrency, onProgress, func(ip string) models.HostResult {
		alive := IsHostAlive(ip, timeout)
		return models.HostResult{IP: ip, Alive: alive}
	})
	if err != nil {
		return nil, err
	}
	report.Hosts = hosts
	report.Status = models.StatusDone
	report.Progress = 100
	return report, nil
}

func RunOSFingerprint(ctx context.Context, opts ScanOptions, onProgress func(done, total int)) (*models.ScanReport, error) {
	normalizeOpts(&opts)
	targets, err := ResolveTargets(opts.Target, opts.MaxHosts)
	if err != nil {
		return nil, err
	}
	timeout := time.Duration(opts.TimeoutMs) * time.Millisecond
	report := &models.ScanReport{
		Generated:    time.Now(),
		ScanType:     models.ScanTypeOSFingerprint,
		Status:       models.StatusRunning,
		Target:       opts.Target,
		PortsScanned: "OS Fingerprinting",
		Notes:        opts.Notes,
	}

	hosts, err := runOverHosts(ctx, targets, opts.HostConcurrency, onProgress, func(ip string) models.HostResult {
		alive := IsHostAlive(ip, timeout)
		hr := models.HostResult{IP: ip, Alive: alive}
		if alive {
			hr.OS = GetOSFingerprint(ip)
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

func runOverHosts(ctx context.Context, targets []string, concurrency int, onProgress func(done, total int), fn func(ip string) models.HostResult) ([]models.HostResult, error) {
	if concurrency < 1 {
		concurrency = 1
	}
	sem := make(chan struct{}, concurrency)
	var wg sync.WaitGroup
	var mu sync.Mutex
	var doneCount int64
	hosts := make([]models.HostResult, 0, len(targets))
	total := len(targets)

	for _, ip := range targets {
		if err := ctx.Err(); err != nil {
			wg.Wait()
			return nil, err
		}
		wg.Add(1)
		sem <- struct{}{}
		go func(ip string) {
			defer wg.Done()
			defer func() { <-sem }()
			if ctx.Err() != nil {
				return
			}
			hr := fn(ip)
			mu.Lock()
			hosts = append(hosts, hr)
			mu.Unlock()
			n := atomic.AddInt64(&doneCount, 1)
			if onProgress != nil {
				onProgress(int(n), total)
			}
		}(ip)
	}
	wg.Wait()
	if err := ctx.Err(); err != nil {
		return hosts, err
	}

	sort.Slice(hosts, func(i, j int) bool {
		return CompareIP(hosts[i].IP, hosts[j].IP)
	})
	return hosts, nil
}
