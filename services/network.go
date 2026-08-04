package services

import (
	"encoding/binary"
	"fmt"
	"net"
	"sort"
	"strconv"
	"strings"
)

func ParsePorts(s string) ([]int, error) {
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
			if lo < 1 || hi > 65535 || lo > 65535 || hi < 1 {
				return nil, fmt.Errorf("port out of range: %s", p)
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
			if v < 1 || v > 65535 {
				return nil, fmt.Errorf("port out of range: %d", v)
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

func ValidateTarget(target string) error {
	target = strings.TrimSpace(target)
	if target == "" {
		return fmt.Errorf("target is required")
	}
	if strings.Contains(target, "/") {
		_, _, err := net.ParseCIDR(target)
		if err != nil {
			return fmt.Errorf("invalid CIDR: %w", err)
		}
		return nil
	}
	if net.ParseIP(target) == nil {
		return fmt.Errorf("invalid IP address: %s", target)
	}
	return nil
}

func ResolveTargets(target string, maxHosts int) ([]string, error) {
	if err := ValidateTarget(target); err != nil {
		return nil, err
	}
	if strings.Contains(target, "/") {
		ips, err := HostsFromCIDR(target)
		if err != nil {
			return nil, err
		}
		if maxHosts > 0 && len(ips) > maxHosts {
			return nil, fmt.Errorf("CIDR expands to %d hosts (max %d)", len(ips), maxHosts)
		}
		return ips, nil
	}
	return []string{target}, nil
}

func HostsFromCIDR(cidr string) ([]string, error) {
	ip, ipnet, err := net.ParseCIDR(cidr)
	if err != nil {
		return nil, err
	}
	var ips []string
	for ip := ip.Mask(ipnet.Mask); ipnet.Contains(ip); incIP(ip) {
		ips = append(ips, ip.String())
	}
	if len(ips) > 2 {
		return ips[1 : len(ips)-1], nil
	}
	return ips, nil
}

func incIP(ip net.IP) {
	for j := len(ip) - 1; j >= 0; j-- {
		ip[j]++
		if ip[j] != 0 {
			break
		}
	}
}

func SortHostsByIP(hosts []string) {
	sort.Slice(hosts, func(i, j int) bool {
		return ipLess(hosts[i], hosts[j])
	})
}

func ipLess(a, b string) bool {
	ai := net.ParseIP(a)
	bi := net.ParseIP(b)
	if ai == nil || bi == nil {
		return a < b
	}
	ai4 := ai.To4()
	bi4 := bi.To4()
	if ai4 != nil && bi4 != nil {
		return binary.BigEndian.Uint32(ai4) < binary.BigEndian.Uint32(bi4)
	}
	return a < b
}

func CompareIP(a, b string) bool {
	return ipLess(a, b)
}
