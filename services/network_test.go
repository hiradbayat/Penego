package services

import (
	"testing"

	"penego/models"
)

func TestParsePorts(t *testing.T) {
	ports, err := ParsePorts("22,80,443")
	if err != nil {
		t.Fatal(err)
	}
	if len(ports) != 3 || ports[0] != 22 || ports[2] != 443 {
		t.Fatalf("unexpected ports: %v", ports)
	}

	ports, err = ParsePorts("5-3")
	if err != nil {
		t.Fatal(err)
	}
	if len(ports) != 3 || ports[0] != 3 || ports[2] != 5 {
		t.Fatalf("range swap failed: %v", ports)
	}

	_, err = ParsePorts("99999")
	if err == nil {
		t.Fatal("expected out of range error")
	}
}

func TestHostsFromCIDR(t *testing.T) {
	ips, err := HostsFromCIDR("192.168.1.0/30")
	if err != nil {
		t.Fatal(err)
	}
	if len(ips) != 2 {
		t.Fatalf("expected 2 hosts, got %d %v", len(ips), ips)
	}
}

func TestValidateTarget(t *testing.T) {
	if err := ValidateTarget("127.0.0.1"); err != nil {
		t.Fatal(err)
	}
	if err := ValidateTarget("10.0.0.0/24"); err != nil {
		t.Fatal(err)
	}
	if err := ValidateTarget("not-an-ip"); err == nil {
		t.Fatal("expected error")
	}
}

func TestCompareIP(t *testing.T) {
	if !CompareIP("192.168.1.2", "192.168.1.10") {
		t.Fatal("numeric order failed")
	}
}

func TestMatchVulns(t *testing.T) {
	host := models.HostResult{
		IP:    "10.0.0.1",
		Alive: true,
		OpenPorts: []models.PortInfo{
			{Port: 22, Open: true, Banner: "SSH-2.0-OpenSSH_7.4", Service: "SSH server"},
		},
	}
	findings := MatchVulns(host)
	if len(findings) == 0 {
		t.Fatal("expected findings for OpenSSH_7.4")
	}
}

func TestBuildNetworkMap(t *testing.T) {
	reports := []models.ScanReport{
		{
			Hosts: []models.HostResult{
				{IP: "10.0.0.1", Alive: true, OpenPorts: []models.PortInfo{{Port: 80, Open: true}}},
				{IP: "10.0.0.2", Alive: true, OpenPorts: []models.PortInfo{{Port: 80, Open: true}}},
			},
		},
	}
	m := BuildNetworkMap(reports)
	if len(m.Nodes) != 2 {
		t.Fatalf("nodes=%d", len(m.Nodes))
	}
	if len(m.Edges) == 0 {
		t.Fatal("expected edges for same /24 and shared port")
	}
}

func TestResolveTargetsMaxHosts(t *testing.T) {
	_, err := ResolveTargets("10.0.0.0/24", 10)
	if err == nil {
		t.Fatal("expected max hosts error")
	}
}
