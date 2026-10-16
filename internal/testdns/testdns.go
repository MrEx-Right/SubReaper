// Package testdns runs an in-process authoritative-style DNS server for tests.
package testdns

import (
	"net"
	"strings"
	"sync"
	"testing"

	"github.com/miekg/dns"
)

// Record describes the answers for one name. Names not present in the zone
// (and not covered by a "*.parent" entry) return NXDOMAIN.
type Record struct {
	CNAME    string
	A        []string
	MX       []string // exchange hosts; "." is a null MX
	NS       []string
	TXT      []string
	ServFail bool
}

// Server is a running fake DNS server.
type Server struct {
	Addr string

	mu   sync.Mutex
	zone map[string]Record
	srv  *dns.Server
}

// Start launches a UDP server answering from zone. It stops when the test ends.
func Start(t testing.TB, zone map[string]Record) *Server {
	t.Helper()
	pc, err := net.ListenPacket("udp", "127.0.0.1:0")
	if err != nil {
		t.Fatalf("listen: %v", err)
	}
	s := &Server{Addr: pc.LocalAddr().String(), zone: make(map[string]Record)}
	for k, v := range zone {
		s.zone[strings.ToLower(dns.Fqdn(k))] = v
	}
	started := make(chan struct{})
	s.srv = &dns.Server{PacketConn: pc, Handler: dns.HandlerFunc(s.handle), NotifyStartedFunc: func() { close(started) }}
	go func() { _ = s.srv.ActivateAndServe() }()
	<-started
	t.Cleanup(func() { _ = s.srv.Shutdown() })
	return s
}

func (s *Server) lookup(name string) (Record, bool) {
	s.mu.Lock()
	defer s.mu.Unlock()
	if r, ok := s.zone[name]; ok {
		return r, true
	}
	if i := strings.IndexByte(name, '.'); i >= 0 {
		if r, ok := s.zone["*."+name[i+1:]]; ok {
			return r, true
		}
	}
	return Record{}, false
}

func (s *Server) handle(w dns.ResponseWriter, req *dns.Msg) {
	m := new(dns.Msg)
	m.SetReply(req)
	m.RecursionAvailable = true
	q := req.Question[0]
	name := strings.ToLower(q.Name)

	rec, ok := s.lookup(name)
	switch {
	case !ok:
		m.Rcode = dns.RcodeNameError
	case rec.ServFail:
		m.Rcode = dns.RcodeServerFailure
	default:
		hdr := func(t uint16) dns.RR_Header {
			return dns.RR_Header{Name: q.Name, Rrtype: t, Class: dns.ClassINET, Ttl: 60}
		}
		if rec.CNAME != "" {
			m.Answer = append(m.Answer, &dns.CNAME{Hdr: hdr(dns.TypeCNAME), Target: dns.Fqdn(rec.CNAME)})
			break
		}
		switch q.Qtype {
		case dns.TypeA:
			for _, ip := range rec.A {
				m.Answer = append(m.Answer, &dns.A{Hdr: hdr(dns.TypeA), A: net.ParseIP(ip)})
			}
		case dns.TypeMX:
			for _, mx := range rec.MX {
				m.Answer = append(m.Answer, &dns.MX{Hdr: hdr(dns.TypeMX), Mx: dns.Fqdn(mx)})
			}
		case dns.TypeNS:
			for _, ns := range rec.NS {
				m.Answer = append(m.Answer, &dns.NS{Hdr: hdr(dns.TypeNS), Ns: dns.Fqdn(ns)})
			}
		case dns.TypeTXT:
			for _, txt := range rec.TXT {
				m.Answer = append(m.Answer, &dns.TXT{Hdr: hdr(dns.TypeTXT), Txt: []string{txt}})
			}
		}
	}
	_ = w.WriteMsg(m)
}

// BlackHole starts a UDP listener that never answers, for timeout tests.
func BlackHole(t testing.TB) string {
	t.Helper()
	pc, err := net.ListenPacket("udp", "127.0.0.1:0")
	if err != nil {
		t.Fatalf("listen: %v", err)
	}
	go func() {
		buf := make([]byte, 512)
		for {
			if _, _, err := pc.ReadFrom(buf); err != nil {
				return
			}
		}
	}()
	t.Cleanup(func() { pc.Close() })
	return pc.LocalAddr().String()
}
