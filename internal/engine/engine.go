// Package engine implements the concurrent scanning engine for SubReaper.
//
// It manages a fixed-size worker pool, a request-level rate limiter shared by
// DNS and HTTP, and clean context-based cancellation.
package engine

import (
	"context"
	"sort"
	"sync"
	"sync/atomic"
	"time"

	"github.com/MrEx-Right/SubReaper/internal/config"
	"github.com/MrEx-Right/SubReaper/internal/models"
	"github.com/MrEx-Right/SubReaper/internal/pipeline"
	"github.com/MrEx-Right/SubReaper/internal/providers"
	"github.com/MrEx-Right/SubReaper/internal/ratelimit"
	"github.com/MrEx-Right/SubReaper/internal/resolver"
)

// ProgressFunc is called after each domain is processed with the total count
// of domains scanned so far and the number of findings.
type ProgressFunc func(scanned, total, findings int)

// Engine manages the concurrent scanning of multiple domains.
type Engine struct {
	cfg      *config.Config
	pipeline *pipeline.Pipeline
}

// New creates a scanning Engine with the given configuration.
func New(cfg *config.Config) *Engine {
	limiter := ratelimit.New(cfg.RateLimit)
	res := resolver.New(cfg.Resolvers, cfg.Timeout, cfg.Retries)
	res.SetLimiter(limiter)
	pipe := pipeline.New(cfg, res, providers.DefaultRegistry())
	pipe.SetLimiter(limiter)

	return &Engine{
		cfg:      cfg,
		pipeline: pipe,
	}
}

// Scan scans a list of domains concurrently and returns an aggregated ScanResult.
// progress is called after each domain completes (may be nil). When ctx is
// cancelled, in-flight work stops and Scan returns the results so far.
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

	domainCh := make(chan string, len(domains))
	for _, d := range domains {
		domainCh <- d
	}
	close(domainCh)

	workerCount := e.cfg.Concurrency
	if workerCount <= 0 {
		workerCount = 50
	}
	if workerCount > len(domains) {
		workerCount = len(domains)
	}
	minSev, _ := models.ParseSeverity(e.cfg.MinSeverity)

	var (
		mu       sync.Mutex // guards result
		scanned  atomic.Int64
		findings atomic.Int64
		wg       sync.WaitGroup
	)

	for i := 0; i < workerCount; i++ {
		wg.Add(1)
		go func() {
			defer wg.Done()
			for domain := range domainCh {
				if ctx.Err() != nil {
					return
				}

				found, err := e.pipeline.Run(ctx, domain)
				if ctx.Err() != nil {
					return // interrupted: the partial result is not an error
				}
				n := scanned.Add(1)

				mu.Lock()
				if err != nil {
					result.Errors = append(result.Errors, models.ScanError{
						Domain:  domain,
						Stage:   "pipeline",
						Message: err.Error(),
					})
				}
				for _, f := range found {
					if f.Severity < minSev {
						continue
					}
					if e.cfg.OnlyVulnerable && !f.IsTakeover() {
						continue
					}
					result.Findings = append(result.Findings, f)
					result.Stats.FindingsTotal++
					result.Stats.Byseverity[f.Severity]++
					findings.Add(1)
				}
				mu.Unlock()

				if progress != nil {
					progress(int(n), len(domains), int(findings.Load()))
				}
			}
		}()
	}

	wg.Wait()

	// Workers finish in any order; report the most severe findings first.
	sort.SliceStable(result.Findings, func(i, j int) bool {
		a, b := result.Findings[i], result.Findings[j]
		if a.Severity != b.Severity {
			return a.Severity > b.Severity
		}
		return a.Subdomain < b.Subdomain
	})

	result.Stats.DomainsScanned = int(scanned.Load())
	result.Interrupted = ctx.Err() != nil
	result.Duration = time.Since(result.StartedAt)
	return result
}
