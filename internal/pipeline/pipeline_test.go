package pipeline

import (
	"context"
	"testing"
	"time"

	"github.com/MrEx-Right/SubReaper/internal/config"
	"github.com/MrEx-Right/SubReaper/internal/models"
	"github.com/MrEx-Right/SubReaper/internal/providers"
	"github.com/MrEx-Right/SubReaper/internal/resolver"
	"github.com/MrEx-Right/SubReaper/internal/testdns"
)

// newDNSOnlyPipeline returns a pipeline against a fake zone with HTTP probing
// and claim checks off, so tests never leave the machine.
func newDNSOnlyPipeline(t *testing.T, zone map[string]testdns.Record) *Pipeline {
	t.Helper()
	srv := testdns.Start(t, zone)
	cfg := config.Default()
	cfg.NoHTTP = true
	cfg.NoVerify = true
	cfg.Timeout = 2 * time.Second
	res := resolver.New([]string{srv.Addr}, cfg.Timeout, 0)
	return New(cfg, res, providers.DefaultRegistry())
}

// healthyRoot gives example.com a complete email policy so that email
// findings do not appear in tests about other records.
var healthyRoot = testdns.Record{
	A:   []string{"192.0.2.1"},
	TXT: []string{"v=spf1 -all"},
}

func baseZone() map[string]testdns.Record {
	return map[string]testdns.Record{
		"example.com":        healthyRoot,
		"_dmarc.example.com": {TXT: []string{"v=DMARC1; p=reject"}},
	}
}

func run(t *testing.T, p *Pipeline, domain string) []*models.Finding {
	t.Helper()
	fs, err := p.Run(context.Background(), domain)
	if err != nil {
		t.Fatalf("Run(%s): %v", domain, err)
	}
	return fs
}

func TestNonexistentNameProducesNothing(t *testing.T) {
	p := newDNSOnlyPipeline(t, baseZone())
	if fs := run(t, p, "nope.example.com"); len(fs) != 0 {
		t.Fatalf("expected no findings for a name that does not exist, got %d: %+v", len(fs), fs[0])
	}
}

func TestDanglingProviderCNAMEIsHigh(t *testing.T) {
	zone := baseZone()
	zone["app.example.com"] = testdns.Record{CNAME: "victim-app.azurewebsites.net"}
	p := newDNSOnlyPipeline(t, zone)

	fs := run(t, p, "app.example.com")
	if len(fs) != 1 {
		t.Fatalf("got %d findings, want 1", len(fs))
	}
	f := fs[0]
	if f.Severity != models.SeverityHigh || f.Type != models.FindingTakeoverPossible {
		t.Fatalf("severity=%s type=%s, want HIGH TAKEOVER_POSSIBLE", f.Severity, f.Type)
	}
	if f.Provider.ProviderName != "Microsoft Azure" || !f.Provider.HasEvidence() {
		t.Fatalf("provider=%+v", f.Provider)
	}
}

func TestDanglingUnknownCNAMEIsLow(t *testing.T) {
	zone := baseZone()
	zone["old.example.com"] = testdns.Record{CNAME: "host.retired-vendor.example"}
	p := newDNSOnlyPipeline(t, zone)

	fs := run(t, p, "old.example.com")
	if len(fs) != 1 || fs[0].Severity != models.SeverityLow || fs[0].Type != models.FindingCNAMEDangling {
		t.Fatalf("findings = %+v", fs)
	}
}

func TestNotVulnerableProviderIsInfo(t *testing.T) {
	zone := baseZone()
	zone["cdn.example.com"] = testdns.Record{CNAME: "d111111abcdef8.cloudfront.net"}
	p := newDNSOnlyPipeline(t, zone)

	fs := run(t, p, "cdn.example.com")
	if len(fs) != 1 || fs[0].Severity != models.SeverityInfo || fs[0].IsTakeover() {
		t.Fatalf("findings = %+v", fs)
	}
}

func TestNullMXIsNotReported(t *testing.T) {
	zone := baseZone()
	r := zone["example.com"]
	r.MX = []string{"."}
	zone["example.com"] = r
	p := newDNSOnlyPipeline(t, zone)

	if fs := run(t, p, "example.com"); len(fs) != 0 {
		t.Fatalf("null MX must not be reported, got %+v", fs[0])
	}
}

func TestDanglingMXAndNS(t *testing.T) {
	zone := baseZone()
	zone["mail.example.com"] = testdns.Record{A: []string{"192.0.2.3"}, MX: []string{"mx.expired-mail.example"}}
	zone["sub.example.com"] = testdns.Record{A: []string{"192.0.2.4"}, NS: []string{"ns1.expired-dns.example"}}
	p := newDNSOnlyPipeline(t, zone)

	fs := run(t, p, "mail.example.com")
	if len(fs) != 1 || fs[0].Type != models.FindingMXDangling {
		t.Fatalf("mail: %+v", fs)
	}
	fs = run(t, p, "sub.example.com")
	if len(fs) != 1 || fs[0].Type != models.FindingNSDangling || fs[0].Severity != models.SeverityMedium {
		t.Fatalf("sub: %+v", fs)
	}
}

func TestEmailFindingsOncePerRegistrableDomain(t *testing.T) {
	p := newDNSOnlyPipeline(t, map[string]testdns.Record{
		"example.co.uk":     {A: []string{"192.0.2.1"}},
		"a.example.co.uk":   {A: []string{"192.0.2.1"}},
		"b.example.co.uk":   {A: []string{"192.0.2.1"}},
		"www.example.co.uk": {A: []string{"192.0.2.1"}},
	})

	first := run(t, p, "a.example.co.uk")
	types := map[models.FindingType]bool{}
	for _, f := range first {
		if f.Subdomain != "example.co.uk" {
			t.Errorf("email finding reported on %q, want the registrable domain", f.Subdomain)
		}
		types[f.Type] = true
	}
	if !types[models.FindingSPFMissing] || !types[models.FindingDMARCMissing] {
		t.Fatalf("want SPF and DMARC missing, got %v", types)
	}
	for _, d := range []string{"b.example.co.uk", "www.example.co.uk"} {
		if fs := run(t, p, d); len(fs) != 0 {
			t.Fatalf("%s repeated email findings: %d", d, len(fs))
		}
	}
}

func TestWildcardReportedOnce(t *testing.T) {
	zone := baseZone()
	zone["*.apps.example.com"] = testdns.Record{CNAME: "gone.azurewebsites.net"}
	p := newDNSOnlyPipeline(t, zone)

	fs := run(t, p, "one.apps.example.com")
	if len(fs) != 1 || fs[0].Subdomain != "*.apps.example.com" || !fs[0].Chain.IsWildcard {
		t.Fatalf("first: %+v", fs)
	}
	if fs := run(t, p, "two.apps.example.com"); len(fs) != 0 {
		t.Fatalf("wildcard reported twice: %+v", fs[0])
	}
}

func TestRootDomain(t *testing.T) {
	cases := map[string]string{
		"api.staging.example.com": "example.com",
		"a.example.co.uk":         "example.co.uk",
		"example.com":             "example.com",
		"co.uk":                   "",
	}
	for in, want := range cases {
		if got := rootDomain(in); got != want {
			t.Errorf("rootDomain(%q) = %q, want %q", in, got, want)
		}
	}
}

func TestSPFSeverity(t *testing.T) {
	cases := map[string]models.Severity{
		"v=spf1 +all":                         models.SeverityHigh,
		"v=spf1 ?all":                         models.SeverityLow,
		"v=spf1 include:_spf.google.com ~all": models.SeverityInfo,
	}
	for spf, want := range cases {
		if got := spfSeverity(spf); got != want {
			t.Errorf("spfSeverity(%q) = %s, want %s", spf, got, want)
		}
	}
}
