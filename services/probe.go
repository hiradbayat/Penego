package services

import (
	"bufio"
	"net"
	"os/exec"
	"runtime"
	"strconv"
	"strings"
	"sync"
	"time"

	"penego/models"
)

var fingerprints = map[string]string{
	"OpenSSH":    "SSH server",
	"Apache":     "Apache HTTP Server",
	"nginx":      "nginx HTTP Server",
	"MySQL":      "MySQL service",
	"PostgreSQL": "PostgreSQL service",
}

func ProbeTCP(ip string, port int, timeout time.Duration, grabBanner bool) models.PortInfo {
	pi := models.PortInfo{Port: port, Open: false}
	addr := net.JoinHostPort(ip, strconv.Itoa(port))
	conn, err := net.DialTimeout("tcp", addr, timeout)
	if err != nil {
		return pi
	}
	defer conn.Close()
	pi.Open = true

	if grabBanner {
		_ = conn.SetReadDeadline(time.Now().Add(2 * time.Second))
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
	return pi
}

func ScanHost(ip string, ports []int, timeout time.Duration, portConcurrency int, grabBanner bool) models.HostResult {
	if portConcurrency < 1 {
		portConcurrency = 1
	}
	host := models.HostResult{IP: ip, Alive: false}
	var wg sync.WaitGroup
	sem := make(chan struct{}, portConcurrency)
	resCh := make(chan models.PortInfo, len(ports))

	for _, p := range ports {
		wg.Add(1)
		sem <- struct{}{}
		go func(port int) {
			defer wg.Done()
			defer func() { <-sem }()
			pi := ProbeTCP(ip, port, timeout, grabBanner)
			if pi.Open {
				resCh <- pi
			}
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

func IsHostAlive(ip string, timeout time.Duration) bool {
	timeoutMs := int(timeout.Milliseconds())
	if timeoutMs < 1 {
		timeoutMs = 1000
	}
	timeoutSec := timeoutMs / 1000
	if timeoutSec < 1 {
		timeoutSec = 1
	}

	var cmd *exec.Cmd
	if runtime.GOOS == "windows" {
		cmd = exec.Command("ping", "-n", "1", "-w", strconv.Itoa(timeoutMs), ip)
	} else {
		cmd = exec.Command("ping", "-c", "1", "-W", strconv.Itoa(timeoutSec), ip)
	}
	return cmd.Run() == nil
}

func GetOSFingerprint(ip string) string {
	cmd := exec.Command("nmap", "-O", ip)
	output, err := cmd.Output()
	if err != nil {
		return "Unknown (error during fingerprinting)"
	}
	lines := strings.Split(string(output), "\n")
	for _, line := range lines {
		if strings.HasPrefix(line, "OS details:") {
			return strings.TrimSpace(strings.TrimPrefix(line, "OS details:"))
		}
	}
	return "Unknown"
}

func CheckPingAvailable() bool {
	var cmd *exec.Cmd
	if runtime.GOOS == "windows" {
		cmd = exec.Command("ping", "-n", "1", "-w", "1000", "127.0.0.1")
	} else {
		cmd = exec.Command("ping", "-c", "1", "-W", "1", "127.0.0.1")
	}
	return cmd.Run() == nil
}

func CheckNmapAvailable() bool {
	cmd := exec.Command("nmap", "--version")
	return cmd.Run() == nil
}
