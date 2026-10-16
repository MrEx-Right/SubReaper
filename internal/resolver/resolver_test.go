package resolver

import (
	"context"
	"testing"
	"time"

	"github.com/MrEx-Right/SubReaper/internal/testdns"
)

func newTestResolver(t *testing.T, zone map[string]testdns.Record) *Resolver {
	t.Helper()
	srv := testdns.Start(t, zone)
	return New([]string{srv.Addr}, 2*time.Second, 0)
}

func TestNormalizeServers(t *testing.T) {
	got, err := NormalizeServers([]string{"8.8.8.8", "1.1.1.1:5353", "2001:4860:4860::8888", "[::1]:53", "# comment", ""})
	if err != nil {
		t.Fatal(err)
	}
	want := []string{"8.8.8.8:53", "1.1.1.1:5353", "[2001:4860:4860::8888]:53", "[::1]:53"}
	if len(got) != len(want) {
		t.Fatalf("got %v, want %v", got, want)
	}
	for i := range want {
		if got[i] != want[i] {
			t.Errorf("entry %d: got %q, want %q", i, got[i], want[i])
		}
	}
	if _, err := NormalizeServers([]string{"bad host"}); err == nil {
		t.Error("expected error for invalid entry")
	}
}

func TestTraverseChain(t *testing.T) {
	r := newTestResolver(t, map[string]testdns.Record{
		"ok.example.com":       {A: []string{"192.0.2.1"}},
		"alias.example.com":    {CNAME: "ok.example.com"},
		"dangling.example.com": {CNAME: "gone.azurewebsites.net"},
		"broken.example.com":   {ServFail: true},
		"loop1.example.com":    {CNAME: "loop2.example.com"},
		"loop2.example.com":    {CNAME: "loop1.example.com"},
	})
	ctx := context.Background()

	t.Run("root NXDOMAIN is not dangling", func(t *testing.T) {
		c, err := r.TraverseChain(ctx, "nothing.example.com")
		if err != nil {
			t.Fatal(err)
		}
		if !c.NotExist || c.IsDangling() {
			t.Fatalf("NotExist=%v dangling=%v, want NotExist and not dangling", c.NotExist, c.IsDangling())
		}
	})

	t.Run("CNAME to NXDOMAIN target is dangling", func(t *testing.T) {
		c, err := r.TraverseChain(ctx, "dangling.example.com")
		if err != nil {
			t.Fatal(err)
		}
		h := c.DanglingHop()
		if h == nil || !h.NXDOMAIN || h.Name != "gone.azurewebsites.net" {
			t.Fatalf("dangling hop = %+v", h)
		}
		if c.FinalCNAME() != "gone.azurewebsites.net" {
			t.Errorf("FinalCNAME = %q", c.FinalCNAME())
		}
	})

	t.Run("healthy alias", func(t *testing.T) {
		c, err := r.TraverseChain(ctx, "alias.example.com")
		if err != nil {
			t.Fatal(err)
		}
		if c.IsDangling() || c.FinalCNAME() != "ok.example.com" {
			t.Fatalf("dangling=%v final=%q", c.IsDangling(), c.FinalCNAME())
		}
	})

	t.Run("SERVFAIL is an error, not dangling", func(t *testing.T) {
		c, err := r.TraverseChain(ctx, "broken.example.com")
		if err == nil {
			t.Fatalf("expected error, got chain %+v", c)
		}
		if c.IsDangling() {
			t.Fatal("SERVFAIL must not mark the chain dangling")
		}
	})

	t.Run("loop", func(t *testing.T) {
		c, err := r.TraverseChain(ctx, "loop1.example.com")
		if err != nil {
			t.Fatal(err)
		}
		if !c.HasLoop || c.IsDangling() {
			t.Fatalf("HasLoop=%v dangling=%v", c.HasLoop, c.IsDangling())
		}
	})
}

func TestUnreachableResolverIsError(t *testing.T) {
	r := New([]string{testdns.BlackHole(t)}, 200*time.Millisecond, 1)
	c, err := r.TraverseChain(context.Background(), "www.example.com")
	if err == nil {
		t.Fatal("expected an error when no resolver answers")
	}
	if c.IsDangling() {
		t.Fatal("timeouts must not mark the chain dangling")
	}
}

func TestCancelInterruptsQuery(t *testing.T) {
	r := New([]string{testdns.BlackHole(t)}, 30*time.Second, 2)
	ctx, cancel := context.WithCancel(context.Background())
	time.AfterFunc(100*time.Millisecond, cancel)
	start := time.Now()
	_, err := r.TraverseChain(ctx, "www.example.com")
	if err == nil {
		t.Fatal("expected cancellation error")
	}
	if d := time.Since(start); d > 2*time.Second {
		t.Fatalf("cancellation took %s, want well under the 30s timeout", d)
	}
}

func TestNullMXIsSkipped(t *testing.T) {
	r := newTestResolver(t, map[string]testdns.Record{
		"example.com":      {A: []string{"192.0.2.1"}, MX: []string{"."}},
		"mail.example.org": {A: []string{"192.0.2.2"}},
		"example.org":      {A: []string{"192.0.2.1"}, MX: []string{"mail.example.org", "gone.example.net"}},
	})
	hops, err := r.ResolveMX(context.Background(), "example.com")
	if err != nil {
		t.Fatal(err)
	}
	if len(hops) != 0 {
		t.Fatalf("null MX should yield no hops, got %+v", hops)
	}

	hops, err = r.ResolveMX(context.Background(), "example.org")
	if err != nil {
		t.Fatal(err)
	}
	if len(hops) != 2 || !hops[0].Resolved || !hops[1].NXDOMAIN {
		t.Fatalf("hops = %+v", hops)
	}
}

func TestResolveTXTNXDOMAIN(t *testing.T) {
	r := newTestResolver(t, nil)
	if _, err := r.ResolveTXT(context.Background(), "missing.example"); err != ErrNXDOMAIN {
		t.Fatalf("err = %v, want ErrNXDOMAIN", err)
	}
}

func TestWildcardSignature(t *testing.T) {
	r := newTestResolver(t, map[string]testdns.Record{
		"*.wild.example.com": {CNAME: "lb.example.net"},
		"lb.example.net":     {A: []string{"192.0.2.9"}},
		"tame.example.com":   {A: []string{"192.0.2.1"}},
	})
	ctx := context.Background()
	sig, err := r.WildcardSignature(ctx, "wild.example.com")
	if err != nil || sig != "cname:lb.example.net" {
		t.Fatalf("sig=%q err=%v", sig, err)
	}
	sig, err = r.WildcardSignature(ctx, "example.com")
	if err != nil || sig != "" {
		t.Fatalf("no wildcard expected, sig=%q err=%v", sig, err)
	}
}
