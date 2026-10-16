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
	"crypto/rand"
	"encoding/hex"
	"errors"
	"fmt"
	mrand "math/rand"
	"net"
	"sort"
	"strings"
	"sync/atomic"
	"time"

	"github.com/MrEx-Right/SubReaper/internal/models"
	"github.com/MrEx-Right/SubReaper/internal/ratelimit"
	"github.com/miekg/dns"
)

const maxCNAMEDepth = 20 // maximum CNAME chain length before aborting (loop guard)

// ErrNXDOMAIN is returned by lookups whose queried name does not exist.
var ErrNXDOMAIN = errors.New("NXDOMAIN")

// Resolver performs DNS queries using a pool of upstream resolvers.
type Resolver struct {
	servers []string      // upstream DNS servers (host:port)
	timeout time.Duration // per-query timeout
	retries int           // retry count per query
	counter atomic.Uint64 // round-robin index
	client  *dns.Client
	tcp     *dns.Client
	limiter *ratelimit.Limiter
}

// New creates a Resolver with the given upstream servers.
// Servers may be given as "host:port" or as a bare IP/host, in which case
// port 53 is assumed. Entries that cannot be parsed are dropped.
func New(servers []string, timeout time.Duration, retries int) *Resolver {
	normalized, _ := NormalizeServers(servers)
	if len(normalized) == 0 {
		normalized = []string{"8.8.8.8:53", "1.1.1.1:53"}
	}
	if timeout <= 0 {
		timeout = 5 * time.Second
	}
	if retries < 0 {
		retries = 0
	}
	return &Resolver{
		servers: normalized,
		timeout: timeout,
		retries: retries,
		client:  &dns.Client{Net: "udp", Timeout: timeout},
		tcp:     &dns.Client{Net: "tcp", Timeout: timeout},
	}
}

// SetLimiter makes every query wait on l before it is sent.
func (r *Resolver) SetLimiter(l *ratelimit.Limiter) { r.limiter = l }

// Servers returns the upstream servers in use.
func (r *Resolver) Servers() []string { return r.servers }

// NormalizeServers converts resolver entries to "host:port" form, adding
// port 53 where it is missing. It returns the valid entries and an error
// listing the entries it could not use.
func NormalizeServers(servers []string) ([]string, error) {
	var out, bad []string
	for _, s := range servers {
		s = strings.TrimSpace(s)
		if s == "" || strings.HasPrefix(s, "#") {
			continue
		}
		if host, port, err := net.SplitHostPort(s); err == nil && host != "" && port != "" {
			out = append(out, net.JoinHostPort(host, port))
			continue
		}
		host := strings.Trim(s, "[]")
		if host == "" || strings.ContainsAny(host, " \t/") {
			bad = append(bad, s)
			continue
		}
		out = append(out, net.JoinHostPort(host, "53"))
	}
	if len(bad) > 0 {
		return out, fmt.Errorf("invalid resolver entries: %s", strings.Join(bad, ", "))
	}
	return out, nil
}

// nextServer returns the next upstream server using round-robin selection.
func (r *Resolver) nextServer() string {
	idx := r.counter.Add(1) - 1
	return r.servers[idx%uint64(len(r.servers))]
}

// exchange sends msg to server and returns as soon as either the response
// arrives or ctx is cancelled. miekg/dns only honours context deadlines, not
// cancellation, so the exchange runs in its own goroutine.
func (r *Resolver) exchange(ctx context.Context, c *dns.Client, msg *dns.Msg, server string) (*dns.Msg, error) {
	type result struct {
		resp *dns.Msg
		err  error
	}
	ch := make(chan result, 1)
	go func() {
		resp, _, err := c.Exchange(msg.Copy(), server)
		ch <- result{resp, err}
	}()
	select {
	case <-ctx.Done():
		return nil, ctx.Err()
	case res := <-ch:
		return res.resp, res.err
	}
}

// query sends a DNS query and returns the response, retrying on failure.
// It falls back to TCP if the UDP response is truncated. SERVFAIL and REFUSED
// answers are retried on the next server and reported as errors, since they
// say nothing about whether the name exists.
func (r *Resolver) query(ctx context.Context, name string, qtype uint16) (*dns.Msg, error) {
	msg := new(dns.Msg)
	msg.SetQuestion(dns.Fqdn(name), qtype)
	msg.RecursionDesired = true

	var lastErr error
	for attempt := 0; attempt <= r.retries; attempt++ {
		if err := r.limiter.Wait(ctx); err != nil {
			return nil, err
		}
		if attempt > 0 {
			jitter := time.Duration(mrand.Intn(100)) * time.Millisecond
			select {
			case <-ctx.Done():
				return nil, ctx.Err()
			case <-time.After(jitter):
			}
		}

		server := r.nextServer()
		resp, err := r.exchange(ctx, r.client, msg, server)
		if err == nil && resp.Truncated {
			resp, err = r.exchange(ctx, r.tcp, msg, server)
		}
		if err != nil {
			if ctx.Err() != nil {
				return nil, ctx.Err()
			}
			lastErr = err
			continue
		}
		if resp.Rcode == dns.RcodeServerFailure || resp.Rcode == dns.RcodeRefused {
			lastErr = fmt.Errorf("%s from %s", dns.RcodeToString[resp.Rcode], server)
			continue
		}
		return resp, nil
	}

	return nil, fmt.Errorf("all %d attempts failed for %s (%s): %w",
		r.retries+1, name, dns.TypeToString[qtype], lastErr)
}

// TraverseChain resolves the full DNS chain for the given domain.
// It follows CNAME records until it reaches an A/AAAA record or a dead end.
//
// A chain is only dangling when a CNAME points at a name that returns
// NXDOMAIN. If the queried name itself does not exist the chain is marked
// NotExist instead. Resolution errors (timeouts, SERVFAIL) are returned as
// errors and never treated as dangling.
func (r *Resolver) TraverseChain(ctx context.Context, domain string) (*models.DNSChain, error) {
	chain := &models.DNSChain{
		Root:          domain,
		DanglingPoint: -1,
	}

	visited := make(map[string]struct{})
	current := domain

	for depth := 0; depth < maxCNAMEDepth; depth++ {
		fqdn := strings.ToLower(dns.Fqdn(current))
		if _, seen := visited[fqdn]; seen {
			chain.HasLoop = true
			return chain, nil
		}
		visited[fqdn] = struct{}{}

		resp, err := r.query(ctx, current, dns.TypeCNAME)
		if err != nil {
			return chain, fmt.Errorf("resolve %s: %w", current, err)
		}

		if resp.Rcode == dns.RcodeNameError {
			if depth == 0 {
				chain.NotExist = true
				return chain, nil
			}
			chain.Hops = append(chain.Hops, models.DNSHop{
				Name:       current,
				RecordType: models.RecordCNAME,
				NXDOMAIN:   true,
			})
			chain.DanglingPoint = len(chain.Hops) - 1
			return chain, nil
		}

		// Use the CNAME owned by the name we asked about; some resolvers
		// return the whole chain in the answer section.
		cnameTarget := ""
		for _, rr := range resp.Answer {
			if cname, ok := rr.(*dns.CNAME); ok && strings.EqualFold(cname.Hdr.Name, fqdn) {
				cnameTarget = strings.ToLower(strings.TrimSuffix(cname.Target, "."))
				break
			}
		}

		if cnameTarget != "" {
			chain.Hops = append(chain.Hops, models.DNSHop{
				Name:       current,
				RecordType: models.RecordCNAME,
				Value:      cnameTarget,
				Resolved:   true,
			})
			current = cnameTarget
			continue
		}

		// No CNAME — resolve address records
		aResp, err := r.query(ctx, current, dns.TypeA)
		if err != nil {
			return chain, fmt.Errorf("resolve %s: %w", current, err)
		}
		if aResp.Rcode == dns.RcodeNameError {
			if depth == 0 {
				chain.NotExist = true
				return chain, nil
			}
			chain.Hops = append(chain.Hops, models.DNSHop{
				Name:       current,
				RecordType: models.RecordA,
				NXDOMAIN:   true,
			})
			chain.DanglingPoint = len(chain.Hops) - 1
			return chain, nil
		}

		for _, rr := range aResp.Answer {
			if a, ok := rr.(*dns.A); ok {
				chain.Hops = append(chain.Hops, models.DNSHop{
					Name:       current,
					RecordType: models.RecordA,
					Value:      a.A.String(),
					Resolved:   true,
				})
			}
		}
		return chain, nil
	}

	// Exceeded max depth
	chain.HasLoop = true
	return chain, nil
}

// WildcardSignature probes a random label directly under parent and returns
// a signature of what the wildcard answers with (see ChainSignature), or ""
// when parent has no wildcard record.
func (r *Resolver) WildcardSignature(ctx context.Context, parent string) (string, error) {
	buf := make([]byte, 6)
	_, _ = rand.Read(buf)
	probe := "subreaper-wc-" + hex.EncodeToString(buf) + "." + parent
	chain, err := r.TraverseChain(ctx, probe)
	if err != nil {
		return "", err
	}
	if chain.NotExist {
		return "", nil
	}
	return ChainSignature(chain), nil
}

// ChainSignature summarises the first answer of a chain: its first CNAME
// target, or the sorted set of A records. Two names answered by the same
// wildcard record have the same signature.
func ChainSignature(chain *models.DNSChain) string {
	if chain == nil || len(chain.Hops) == 0 {
		return ""
	}
	if chain.Hops[0].RecordType == models.RecordCNAME {
		return "cname:" + chain.Hops[0].Value
	}
	var ips []string
	for _, h := range chain.Hops {
		if h.RecordType == models.RecordA && h.Value != "" {
			ips = append(ips, h.Value)
		}
	}
	sort.Strings(ips)
	return "a:" + strings.Join(ips, ",")
}

// hostExists reports whether host has any address record. NXDOMAIN is
// reported as (false, true, nil); a host that exists returns (true, false, nil).
func (r *Resolver) hostExists(ctx context.Context, host string) (resolved, nxdomain bool, err error) {
	for _, qt := range []uint16{dns.TypeA, dns.TypeAAAA} {
		resp, err := r.query(ctx, host, qt)
		if err != nil {
			return false, false, err
		}
		if resp.Rcode == dns.RcodeNameError {
			return false, true, nil
		}
		if len(resp.Answer) > 0 {
			return true, false, nil
		}
	}
	return false, false, nil
}

// IsNXDOMAIN reports whether host returns NXDOMAIN. Resolution errors are
// returned as errors, never as NXDOMAIN.
func (r *Resolver) IsNXDOMAIN(ctx context.Context, host string) (bool, error) {
	_, nx, err := r.hostExists(ctx, host)
	return nx, err
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
		if !ok || !strings.EqualFold(ns.Hdr.Name, dns.Fqdn(domain)) {
			continue
		}
		nsHost := strings.TrimSuffix(ns.Ns, ".")
		if nsHost == "" {
			continue
		}
		resolved, nxdomain, err := r.hostExists(ctx, nsHost)
		if err != nil {
			continue // unknown state is not evidence of anything
		}
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
// A null MX record ("MX 0 .", RFC 7505) means the domain accepts no mail and is skipped.
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
		if mxHost == "" {
			continue // null MX
		}
		resolved, nxdomain, err := r.hostExists(ctx, mxHost)
		if err != nil {
			continue
		}
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
// It returns ErrNXDOMAIN when the domain does not exist.
func (r *Resolver) ResolveTXT(ctx context.Context, domain string) ([]string, error) {
	resp, err := r.query(ctx, domain, dns.TypeTXT)
	if err != nil {
		return nil, err
	}
	if resp.Rcode == dns.RcodeNameError {
		return nil, ErrNXDOMAIN
	}

	var records []string
	for _, rr := range resp.Answer {
		if txt, ok := rr.(*dns.TXT); ok {
			records = append(records, strings.Join(txt.Txt, ""))
		}
	}

	// Also query _dmarc.<domain>
	dmarcResp, err := r.query(ctx, "_dmarc."+domain, dns.TypeTXT)
	if err != nil {
		return nil, err
	}
	if dmarcResp.Rcode != dns.RcodeNameError {
		for _, rr := range dmarcResp.Answer {
			if txt, ok := rr.(*dns.TXT); ok {
				records = append(records, "dmarc:"+strings.Join(txt.Txt, ""))
			}
		}
	}

	return records, nil
}
