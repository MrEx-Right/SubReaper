package engine

import (
	"context"
	"fmt"
	"testing"
	"time"

	"github.com/MrEx-Right/SubReaper/internal/config"
	"github.com/MrEx-Right/SubReaper/internal/testdns"
)

// Regression: with more workers than the old 64-slot error channel, a
// cancelled scan used to deadlock forever.
func TestCancelWithHighConcurrencyReturns(t *testing.T) {
	cfg := config.Default()
	cfg.Resolvers = []string{testdns.BlackHole(t)}
	cfg.Concurrency = 200
	cfg.RateLimit = 0
	cfg.Timeout = 30 * time.Second
	cfg.NoHTTP = true

	var domains []string
	for i := 0; i < 500; i++ {
		domains = append(domains, fmt.Sprintf("h%d.example.com", i))
	}

	ctx, cancel := context.WithCancel(context.Background())
	time.AfterFunc(300*time.Millisecond, cancel)

	done := make(chan struct{})
	var interrupted bool
	go func() {
		res := New(cfg).Scan(ctx, domains, nil)
		interrupted = res.Interrupted
		close(done)
	}()

	select {
	case <-done:
		if !interrupted {
			t.Error("result should be marked interrupted")
		}
	case <-time.After(5 * time.Second):
		t.Fatal("Scan did not return within 5s of cancellation")
	}
}

func TestErrorsAreCollected(t *testing.T) {
	cfg := config.Default()
	cfg.Resolvers = []string{testdns.BlackHole(t)}
	cfg.Concurrency = 100
	cfg.RateLimit = 0
	cfg.Timeout = 100 * time.Millisecond
	cfg.Retries = 0
	cfg.NoHTTP = true

	var domains []string
	for i := 0; i < 150; i++ {
		domains = append(domains, fmt.Sprintf("e%d.example.com", i))
	}
	res := New(cfg).Scan(context.Background(), domains, nil)
	if len(res.Errors) != len(domains) {
		t.Fatalf("errors = %d, want %d", len(res.Errors), len(domains))
	}
	if len(res.Findings) != 0 {
		t.Fatalf("unanswered queries must not produce findings, got %d", len(res.Findings))
	}
}
