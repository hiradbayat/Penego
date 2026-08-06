package services

import (
	_ "embed"
	"encoding/json"
	"fmt"
	"regexp"
	"strconv"
	"sync"

	"penego/models"
)

//go:embed vuln-rules.json
var embeddedRulesJSON []byte

type VulnRulePack struct {
	Version string     `json:"version"`
	Rules   []VulnRule `json:"rules"`
}

type VulnRule struct {
	ID          string `json:"id"`
	Product     string `json:"product"`
	BannerRegex string `json:"banner_regex"`
	MaxMajor    *int   `json:"max_major"`
	Severity    string `json:"severity"`
	Title       string `json:"title"`
	Description string `json:"description"`
	CVE         string `json:"cve"`
	Remediation string `json:"remediation"`
	re          *regexp.Regexp
}

var (
	ruleOnce sync.Once
	rulePack VulnRulePack
	ruleErr  error
)

func LoadVulnRules(paths ...string) (VulnRulePack, error) {
	ruleOnce.Do(func() {
		if err := json.Unmarshal(embeddedRulesJSON, &rulePack); err != nil {
			ruleErr = fmt.Errorf("embedded rules: %w", err)
			return
		}
		for i := range rulePack.Rules {
			re, err := regexp.Compile(rulePack.Rules[i].BannerRegex)
			if err != nil {
				ruleErr = fmt.Errorf("rule %s: %w", rulePack.Rules[i].ID, err)
				return
			}
			rulePack.Rules[i].re = re
		}
	})
	return rulePack, ruleErr
}

func MatchVulnRules(host models.HostResult) []models.Finding {
	pack, err := LoadVulnRules()
	if err != nil || len(pack.Rules) == 0 {
		return convertLegacyVulns(MatchVulns(host))
	}
	findings := make([]models.Finding, 0)
	for _, p := range host.OpenPorts {
		text := p.Banner + " " + p.Service
		for _, rule := range pack.Rules {
			if rule.re == nil || !rule.re.MatchString(text) {
				continue
			}
			if rule.MaxMajor != nil {
				m := rule.re.FindStringSubmatch(text)
				if len(m) >= 2 {
					maj, _ := strconv.Atoi(m[1])
					if maj > *rule.MaxMajor {
						continue
					}
				}
			}
			findings = append(findings, models.Finding{
				Port:        p.Port,
				Severity:    rule.Severity,
				Status:      models.FindingOpen,
				Title:       rule.Title,
				Description: rule.Description,
				CVE:         rule.CVE,
				Evidence:    stringsTrim(p.Banner),
				Remediation: rule.Remediation,
				Category:    "vuln",
			})
		}
	}
	return findings
}

func convertLegacyVulns(v []models.VulnFinding) []models.Finding {
	out := make([]models.Finding, 0, len(v))
	for _, x := range v {
		out = append(out, models.Finding{
			Port:        x.Port,
			Severity:    x.Severity,
			Status:      models.FindingOpen,
			Title:       x.Title,
			Description: x.Description,
			CVE:         x.CVE,
			Evidence:    x.Evidence,
			Category:    "vuln",
		})
	}
	return out
}

func stringsTrim(s string) string {
	if len(s) > 512 {
		return s[:512]
	}
	return s
}
