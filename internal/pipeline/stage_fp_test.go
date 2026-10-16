package pipeline

import (
	"testing"

	"github.com/MrEx-Right/SubReaper/internal/models"
	"github.com/MrEx-Right/SubReaper/internal/providers"
)

func cnameChain(target string, nx bool) *models.DNSChain {
	c := &models.DNSChain{Root: "sub.victim.com", DanglingPoint: -1, Hops: []models.DNSHop{
		{Name: "sub.victim.com", RecordType: models.RecordCNAME, Value: target, Resolved: true},
	}}
	if nx {
		c.Hops = append(c.Hops, models.DNSHop{Name: target, RecordType: models.RecordCNAME, NXDOMAIN: true})
		c.DanglingPoint = 1
	} else {
		c.Hops = append(c.Hops, models.DNSHop{Name: target, RecordType: models.RecordA, Value: "192.0.2.1", Resolved: true})
	}
	return c
}

func TestFingerprintNXDOMAINTarget(t *testing.T) {
	probes := []*models.HTTPProbe{{URL: "https://sub.victim.com", Error: "no such host"}}
	m := stageFingerprint(cnameChain("victim.azurewebsites.net", true), probes, providers.DefaultRegistry())
	if !m.IsIdentified() || !m.HasEvidence() || m.Confidence < 80 {
		t.Fatalf("match = %+v", m)
	}
}

func TestFingerprintUnclaimedGitHubPages(t *testing.T) {
	probe := &models.HTTPProbe{
		URL:        "https://sub.victim.com",
		StatusCode: 404,
		Headers:    map[string][]string{"Server": {"GitHub.com"}},
		Body:       []byte("<h1>404</h1><p><strong>There isn't a GitHub Pages site here.</strong></p>"),
	}
	m := stageFingerprint(cnameChain("someone.github.io", false), []*models.HTTPProbe{probe, probe}, providers.DefaultRegistry())
	if m.ProviderName != "GitHub Pages" || !m.IsIdentified() || !m.HasEvidence() {
		t.Fatalf("match = %+v", m)
	}
	// The same evidence seen on two probes must not be counted twice.
	if m.Confidence != 40+20+5+25 {
		t.Errorf("confidence = %d, want 90 (signals deduplicated)", m.Confidence)
	}
}

func TestFingerprintHealthySiteHasNoEvidence(t *testing.T) {
	probe := &models.HTTPProbe{
		URL:        "https://sub.victim.com",
		StatusCode: 200,
		Headers:    map[string][]string{"Server": {"GitHub.com"}, "X-Github-Request-Id": {"abc"}},
		Body:       []byte("<html>Welcome to our docs</html>"),
	}
	m := stageFingerprint(cnameChain("someone.github.io", false), []*models.HTTPProbe{probe}, providers.DefaultRegistry())
	if m.HasEvidence() {
		t.Fatalf("a working site must have no takeover evidence: %+v", m)
	}
}

func TestFingerprintNeedsProviderCNAME(t *testing.T) {
	probe := &models.HTTPProbe{
		URL:        "https://sub.victim.com",
		StatusCode: 404,
		Body:       []byte("There isn't a GitHub Pages site here."),
	}
	m := stageFingerprint(cnameChain("lb.victim-cdn.net", false), []*models.HTTPProbe{probe}, providers.DefaultRegistry())
	if m.ProviderName != "" {
		t.Fatalf("body text alone must not identify a provider: %+v", m)
	}
}
