// Package engine implements the concurrent scanning engine for SubReaper.
//
// It manages a fixed-size worker pool, a token-bucket rate limiter, and
// clean context-based cancellation. Results are fanned in from all workers
// to a single result channel.
package engine

import (
	"context"
	"sync"
	"sync/atomic"
	"time"

	"github.com/MrEx-Right/SubReaper/internal/config"
	"github.com/MrEx-Right/SubReaper/internal/models"
	"github.com/MrEx-Right/SubReaper/internal/pipeline"
	"github.com/MrEx-Right/SubReaper/internal/providers"
	"github.com/MrEx-Right/SubReaper/internal/resolver"
)

// ProgressFunc is called after each domain is processed with the total count
// of domains scanned so far and the number of findings.
type ProgressFunc func(scanned, total, findings int)

// Engine manages the concurrent scanning of multiple domains.
type Engine struct {
	cfg      *config.Config
	pipeline *pipeline.Pipeline
	stats    atomicStats
}

type atomicStats struct {
	scanned  atomic.Int64
	findings atomic.Int64
	errors   atomic.Int64
}

// New creates a scanning Engine with the given configuration.
func New(cfg *config.Config) *Engine {
	res := resolver.New(cfg.Resolvers, cfg.Timeout, cfg.Retries)
	reg := providers.DefaultRegistry()
	pipe := pipeline.New(cfg, res, reg)

	return &Engine{
		cfg:      cfg,
		pipeline: pipe,
	}
}

// Scan scans a list of domains concurrently and returns an aggregated ScanResult.
// progress is called after each domain completes (may be nil).
func (e *Engine) Scan(ctx context.Context, domains []string, progress ProgressFunc) *models.ScanResult {
	result := &models.ScanResult{
		StartedAt: time.Now(),
		Stats: models.ScanStats{
			Byseverity: make(map[models.Severity]int),
		},
	}

	if len(domains) == 0 {
		result.Duration = time.Since(result.StartedAt)
		return result
	}

	result.Stats.DomainsScanned = len(domains)

	// Channel of domains to process
	domainCh := make(chan string, len(domains))
	for _, d := range domains {
		domainCh <- d
	}
	close(domainCh)

	// Result fan-in channel
	findingCh := make(chan *models.Finding, 64)
	errCh := make(chan models.ScanError, 64)

	// Rate limiter: token bucket
	rateLimiter := newTokenBucket(e.cfg.RateLimit)

	// Start worker pool
	workerCount := e.cfg.Concurrency
	if workerCount <= 0 {
		workerCount = 50
	}

	var wg sync.WaitGroup
	for i := 0; i < workerCount; i++ {
		wg.Add(1)
		go func() {
			defer wg.Done()
			for domain := range domainCh {
				select {
				case <-ctx.Done():
					return
				default:
				}

				// Acquire rate limit token
				rateLimiter.Wait(ctx)

				finding, err := e.pipeline.Run(ctx, domain)
				e.stats.scanned.Add(1)

				if err != nil {
					errCh <- models.ScanError{
						Domain:  domain,
						Stage:   "pipeline",
						Message: err.Error(),
					}
					e.stats.errors.Add(1)
				} else if finding != nil {
					// Apply severity filter
					if severityGTE(finding.Severity, minSeverity(e.cfg.MinSeverity)) {
						if !e.cfg.OnlyVulnerable || finding.IsTakeover() {
							findingCh <- finding
							e.stats.findings.Add(1)
						}
					}
				}

				if progress != nil {
					progress(
						int(e.stats.scanned.Load()),
						len(domains),
						int(e.stats.findings.Load()),
					)
				}
			}
		}()
	}

	// Close result channels when all workers are done
	go func() {
		wg.Wait()
		close(findingCh)
		close(errCh)
	}()

	// Collect results
	for finding := range findingCh {
		result.Findings = append(result.Findings, finding)
		result.Stats.FindingsTotal++
		result.Stats.Byseverity[finding.Severity]++
	}
	for err := range errCh {
		result.Errors = append(result.Errors, err)
	}

	result.Duration = time.Since(result.StartedAt)
	return result
}

// tokenBucket is a simple token-bucket rate limiter.
type tokenBucket struct {
	tokens chan struct{}
}

func newTokenBucket(ratePerSecond int) *tokenBucket {
	if ratePerSecond <= 0 {
		ratePerSecond = 100
	}
	tb := &tokenBucket{
		tokens: make(chan struct{}, ratePerSecond),
	}
	// Refill at the specified rate
	go func() {
		ticker := time.NewTicker(time.Second / time.Duration(ratePerSecond))
		defer ticker.Stop()
		for range ticker.C {
			select {
			case tb.tokens <- struct{}{}:
			default:
				// Bucket full
			}
		}
	}()
	// Pre-fill the bucket
	for i := 0; i < ratePerSecond; i++ {
		select {
		case tb.tokens <- struct{}{}:
		default:
		}
	}
	return tb
}

func (tb *tokenBucket) Wait(ctx context.Context) {
	select {
	case <-tb.tokens:
	case <-ctx.Done():
	}
}

// severityGTE returns true if a >= b.
func severityGTE(a, b models.Severity) bool {
	return a >= b
}

// minSeverity parses a severity string into a Severity value.
func minSeverity(s string) models.Severity {
	switch s {
	case "low":
		return models.SeverityLow
	case "medium":
		return models.SeverityMedium
	case "high":
		return models.SeverityHigh
	case "critical":
		return models.SeverityCritical
	default:
		return models.SeverityInfo
	}
}
