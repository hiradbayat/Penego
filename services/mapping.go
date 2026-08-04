package services

import (
	"fmt"
	"net"
	"strings"

	"penego/models"
)

type MapNode struct {
	ID    string `json:"id"`
	Label string `json:"label"`
	Alive bool   `json:"alive"`
	OS    string `json:"os,omitempty"`
	Ports []int  `json:"ports,omitempty"`
}

type MapEdge struct {
	Source string `json:"source"`
	Target string `json:"target"`
	Label  string `json:"label"`
}

type NetworkMap struct {
	Nodes []MapNode `json:"nodes"`
	Edges []MapEdge `json:"edges"`
}

func BuildNetworkMap(reports []models.ScanReport) NetworkMap {
	nodeMap := map[string]*MapNode{}
	for _, r := range reports {
		for _, h := range r.Hosts {
			n, ok := nodeMap[h.IP]
			if !ok {
				n = &MapNode{ID: h.IP, Label: h.IP, Alive: h.Alive, OS: h.OS}
				nodeMap[h.IP] = n
			}
			if h.Alive {
				n.Alive = true
			}
			if h.OS != "" {
				n.OS = h.OS
			}
			for _, p := range h.OpenPorts {
				n.Ports = appendUniqueInt(n.Ports, p.Port)
			}
		}
	}

	nodes := make([]MapNode, 0, len(nodeMap))
	for _, n := range nodeMap {
		nodes = append(nodes, *n)
	}

	// Edges: hosts in same /24 subnet
	edges := make([]MapEdge, 0)
	seen := map[string]bool{}
	ips := make([]string, 0, len(nodes))
	for _, n := range nodes {
		ips = append(ips, n.ID)
	}
	for i := 0; i < len(ips); i++ {
		for j := i + 1; j < len(ips); j++ {
			a, b := ips[i], ips[j]
			if sameSubnet24(a, b) {
				key := a + "|" + b
				if a > b {
					key = b + "|" + a
				}
				if seen[key] {
					continue
				}
				seen[key] = true
				edges = append(edges, MapEdge{Source: a, Target: b, Label: "/24"})
			}
		}
	}

	// Edges: shared open ports (service affinity)
	portOwners := map[int][]string{}
	for _, n := range nodes {
		for _, p := range n.Ports {
			portOwners[p] = append(portOwners[p], n.ID)
		}
	}
	for port, owners := range portOwners {
		if len(owners) < 2 || len(owners) > 20 {
			continue
		}
		for i := 0; i < len(owners); i++ {
			for j := i + 1; j < len(owners); j++ {
				a, b := owners[i], owners[j]
				key := fmt.Sprintf("p%d:%s|%s", port, a, b)
				if a > b {
					key = fmt.Sprintf("p%d:%s|%s", port, b, a)
				}
				if seen[key] {
					continue
				}
				seen[key] = true
				edges = append(edges, MapEdge{
					Source: a,
					Target: b,
					Label:  fmt.Sprintf("port %d", port),
				})
			}
		}
	}

	return NetworkMap{Nodes: nodes, Edges: edges}
}

func sameSubnet24(a, b string) bool {
	ai := net.ParseIP(a).To4()
	bi := net.ParseIP(b).To4()
	if ai == nil || bi == nil {
		return false
	}
	return ai[0] == bi[0] && ai[1] == bi[1] && ai[2] == bi[2]
}

func appendUniqueInt(s []int, v int) []int {
	for _, x := range s {
		if x == v {
			return s
		}
	}
	return append(s, v)
}

func SubnetLabel(ip string) string {
	parts := strings.Split(ip, ".")
	if len(parts) != 4 {
		return ip
	}
	return parts[0] + "." + parts[1] + "." + parts[2] + ".0/24"
}
