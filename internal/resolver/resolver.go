// Package resolver provides a custom DNS resolution engine for SubReaper.
//
// It uses github.com/miekg/dns for low-level DNS control, enabling:
//   - Full CNAME chain traversal with loop detection
//   - Wildcard record detection
//   - Multiple upstream resolvers with round-robin fallback
//   - NS and MX record analysis
package resolver

import (
	"context"
	"fmt"
	"math/rand"
	"net"
	"strings"
	"sync/atomic"
	"time"

	"github.com/MrEx-Right/SubReaper/internal/models"
	"github.com/miekg/dns"
)

const (
	maxCNAMEDepth = 20   // maximum CNAME chain length before aborting (loop guard)
	bodyReadLimit = 4096 // max bytes read from DNS response
)

// Resolver performs DNS queries using a pool of upstream resolvers.
type Resolver struct {
	servers []string      // upstream DNS servers (host:port)
	timeout time.Duration // per-query timeout
	retries int           // retry count per query
	counter atomic.Uint64 // round-robin index
	client  *dns.Client
}

// New creates a Resolver with the given upstream servers.
// servers must be in "host:port" format (e.g. "8.8.8.8:53").
func New(servers []string, timeout time.Duration, retries int) *Resolver {
	if len(servers) == 0 {
		servers = []string{"8.8.8.8:53", "1.1.1.1:53"}
	}
	return &Resolver{
		servers: servers,
		timeout: timeout,
		retries: retries,
		client: &dns.Client{
			Net:     "udp",
			Timeout: timeout,
		},
	}
}

// nextServer returns the next upstream server using round-robin selection.
func (r *Resolver) nextServer() string {
	idx := r.counter.Add(1) - 1
	return r.servers[idx%uint64(len(r.servers))]
}

// query sends a DNS query and returns the response, retrying on failure.
// It automatically falls back to TCP if the UDP response is truncated.
func (r *Resolver) query(ctx context.Context, name string, qtype uint16) (*dns.Msg, error) {
	msg := new(dns.Msg)
	msg.SetQuestion(dns.Fqdn(name), qtype)
	msg.RecursionDesired = true

	var lastErr error
	for attempt := 0; attempt <= r.retries; attempt++ {
		select {
		case <-ctx.Done():
			return nil, ctx.Err()
		default:
		}

		server := r.nextServer()
		resp, _, err := r.client.ExchangeContext(ctx, msg, server)
		if err != nil {
			lastErr = err
			// Jitter before retry
			if attempt < r.retries {
				jitter := time.Duration(rand.Intn(100)) * time.Millisecond
				time.Sleep(jitter)
			}
			continue
		}

		// If truncated, retry over TCP
		if resp.Truncated {
			tcpClient := &dns.Client{Net: "tcp", Timeout: r.timeout}
			resp, _, err = tcpClient.ExchangeContext(ctx, msg, server)
			if err != nil {
				lastErr = err
				continue
			}
		}

		return resp, nil
	}

	return nil, fmt.Errorf("all %d attempts failed for %s (type %d): %w",
		r.retries+1, name, qtype, lastErr)
}

// TraverseChain resolves the full DNS chain for the given domain.
// It follows CNAME records until it reaches an A/AAAA record or a dead end.
// Loop detection is performed via a visited set.
func (r *Resolver) TraverseChain(ctx context.Context, domain string) (*models.DNSChain, error) {
	chain := &models.DNSChain{
		Root:          domain,
		DanglingPoint: -1,
	}

	visited := make(map[string]struct{})
	current := domain

	for depth := 0; depth < maxCNAMEDepth; depth++ {
		select {
		case <-ctx.Done():
			return chain, ctx.Err()
		default:
		}

		fqdn := dns.Fqdn(current)
		if _, seen := visited[fqdn]; seen {
			chain.HasLoop = true
			return chain, nil
		}
		visited[fqdn] = struct{}{}

		// Query for CNAME first
		resp, err := r.query(ctx, current, dns.TypeCNAME)
		if err != nil {
			hop := models.DNSHop{
				Name:       current,
				RecordType: models.RecordCNAME,
				Value:      "",
				Resolved:   false,
			}
			chain.Hops = append(chain.Hops, hop)
			chain.DanglingPoint = len(chain.Hops) - 1
			return chain, nil
		}

		if resp.Rcode == dns.RcodeNameError { // NXDOMAIN
			hop := models.DNSHop{
				Name:       current,
				RecordType: models.RecordCNAME,
				Value:      "",
				Resolved:   false,
				NXDOMAIN:   true,
			}
			chain.Hops = append(chain.Hops, hop)
			chain.DanglingPoint = len(chain.Hops) - 1
			return chain, nil
		}

		// Check for CNAME records in the answer
		cnameTarget := ""
		for _, rr := range resp.Answer {
			if cname, ok := rr.(*dns.CNAME); ok {
				cnameTarget = strings.TrimSuffix(cname.Target, ".")
				break
			}
		}

		if cnameTarget != "" {
			hop := models.DNSHop{
				Name:       current,
				RecordType: models.RecordCNAME,
				Value:      cnameTarget,
				Resolved:   true,
			}
			chain.Hops = append(chain.Hops, hop)
			current = cnameTarget
			continue
		}

		// No CNAME — try A record
		aResp, err := r.query(ctx, current, dns.TypeA)
		if err != nil || aResp.Rcode == dns.RcodeNameError {
			hop := models.DNSHop{
				Name:       current,
				RecordType: models.RecordA,
				Value:      "",
				Resolved:   false,
				NXDOMAIN:   aResp != nil && aResp.Rcode == dns.RcodeNameError,
			}
			chain.Hops = append(chain.Hops, hop)
			chain.DanglingPoint = len(chain.Hops) - 1
			return chain, nil
		}

		// Collect A records
		for _, rr := range aResp.Answer {
			if a, ok := rr.(*dns.A); ok {
				hop := models.DNSHop{
					Name:       current,
					RecordType: models.RecordA,
					Value:      a.A.String(),
					Resolved:   true,
				}
				chain.Hops = append(chain.Hops, hop)
			}
		}

		// Successfully resolved to IPs — no dangling point
		return chain, nil
	}

	// Exceeded max depth
	chain.HasLoop = true
	return chain, nil
}

// CheckWildcard determines whether the domain has a wildcard DNS record.
// It generates a random subdomain and checks if it resolves.
// If it does, *.domain is a wildcard and bruteforce results will be unreliable.
func (r *Resolver) CheckWildcard(ctx context.Context, domain string) (bool, error) {
	// Use a fixed random-looking subdomain — deterministic for reproducibility
	probe := fmt.Sprintf("subreaper-wildcard-check-7f3a9c.%s", domain)
	resp, err := r.query(ctx, probe, dns.TypeA)
	if err != nil {
		// Query failure is not a wildcard
		return false, nil
	}
	if resp.Rcode == dns.RcodeNameError {
		return false, nil
	}
	// Any non-NXDOMAIN response suggests a wildcard
	return len(resp.Answer) > 0, nil
}

// ResolveNS returns the nameservers for the given domain and checks if they resolve.
func (r *Resolver) ResolveNS(ctx context.Context, domain string) ([]models.DNSHop, error) {
	resp, err := r.query(ctx, domain, dns.TypeNS)
	if err != nil {
		return nil, err
	}

	var hops []models.DNSHop
	for _, rr := range resp.Answer {
		ns, ok := rr.(*dns.NS)
		if !ok {
			continue
		}
		nsHost := strings.TrimSuffix(ns.Ns, ".")

		// Check if the nameserver itself resolves
		aResp, err := r.query(ctx, nsHost, dns.TypeA)
		resolved := err == nil && aResp.Rcode != dns.RcodeNameError && len(aResp.Answer) > 0
		nxdomain := err == nil && aResp.Rcode == dns.RcodeNameError

		hops = append(hops, models.DNSHop{
			Name:       domain,
			RecordType: models.RecordNS,
			Value:      nsHost,
			Resolved:   resolved,
			NXDOMAIN:   nxdomain,
		})
	}
	return hops, nil
}

// ResolveMX returns the mail exchangers for the given domain and checks if they resolve.
func (r *Resolver) ResolveMX(ctx context.Context, domain string) ([]models.DNSHop, error) {
	resp, err := r.query(ctx, domain, dns.TypeMX)
	if err != nil {
		return nil, err
	}

	var hops []models.DNSHop
	for _, rr := range resp.Answer {
		mx, ok := rr.(*dns.MX)
		if !ok {
			continue
		}
		mxHost := strings.TrimSuffix(mx.Mx, ".")

		aResp, err := r.query(ctx, mxHost, dns.TypeA)
		resolved := err == nil && aResp.Rcode != dns.RcodeNameError && len(aResp.Answer) > 0
		nxdomain := err == nil && aResp.Rcode == dns.RcodeNameError

		hops = append(hops, models.DNSHop{
			Name:       domain,
			RecordType: models.RecordMX,
			Value:      mxHost,
			Resolved:   resolved,
			NXDOMAIN:   nxdomain,
		})
	}
	return hops, nil
}

// ResolveIPs returns all A and AAAA records for the given domain.
func (r *Resolver) ResolveIPs(ctx context.Context, domain string) ([]net.IP, error) {
	var ips []net.IP

	aResp, err := r.query(ctx, domain, dns.TypeA)
	if err == nil && aResp.Rcode != dns.RcodeNameError {
		for _, rr := range aResp.Answer {
			if a, ok := rr.(*dns.A); ok {
				ips = append(ips, a.A)
			}
		}
	}

	aaaaResp, err := r.query(ctx, domain, dns.TypeAAAA)
	if err == nil && aaaaResp.Rcode != dns.RcodeNameError {
		for _, rr := range aaaaResp.Answer {
			if aaaa, ok := rr.(*dns.AAAA); ok {
				ips = append(ips, aaaa.AAAA)
			}
		}
	}

	return ips, nil
}

// ResolveTXT returns all TXT record values for the given domain.
// It also checks _dmarc.<domain> and returns those values with a "dmarc:" prefix
// so callers can distinguish DMARC records from plain TXT records.
func (r *Resolver) ResolveTXT(ctx context.Context, domain string) ([]string, error) {
	resp, err := r.query(ctx, domain, dns.TypeTXT)
	if err != nil {
		return nil, err
	}

	var records []string
	for _, rr := range resp.Answer {
		if txt, ok := rr.(*dns.TXT); ok {
			records = append(records, strings.Join(txt.Txt, ""))
		}
	}

	// Also query _dmarc.<domain>
	dmarcDomain := "_dmarc." + domain
	dmarcResp, err := r.query(ctx, dmarcDomain, dns.TypeTXT)
	if err == nil && dmarcResp.Rcode != dns.RcodeNameError {
		for _, rr := range dmarcResp.Answer {
			if txt, ok := rr.(*dns.TXT); ok {
				records = append(records, "dmarc:"+strings.Join(txt.Txt, ""))
			}
		}
	}

	return records, nil
}
