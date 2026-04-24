package dns

import (
	"context"
	"errors"
	"fmt"
	"net"
	"os"
	"strings"
	"sync"
	"time"

	codedns "codeberg.org/miekg/dns"
)

var ErrUnsupported = errors.New("lookup not supported by resolver")
var ErrNoResolver = errors.New("no DNS resolver configured")

const (
	TypeSOA    uint16 = codedns.TypeSOA
	TypeDNSKEY uint16 = codedns.TypeDNSKEY
)

type SOA struct {
	NS      string `json:"ns"`
	MBox    string `json:"mbox"`
	Serial  uint32 `json:"serial"`
	Refresh uint32 `json:"refresh"`
	Retry   uint32 `json:"retry"`
	Expire  uint32 `json:"expire"`
	MinTTL  uint32 `json:"minTTL"`
}

type QueryMetric struct {
	Name       string `json:"name"`
	Type       string `json:"type"`
	DurationMS int64  `json:"durationMs"`
	Error      string `json:"error,omitempty"`
}

type DNSSECStatus struct {
	Validated bool   `json:"validated"`
	Source    string `json:"source,omitempty"`
}

type DNSResponse struct {
	SOA               *SOA
	AuthenticatedData bool
}

type Resolver interface {
	LookupMX(ctx context.Context, domain string) ([]*net.MX, error)
	LookupTXT(ctx context.Context, name string) ([]string, error)
	LookupIPAddr(ctx context.Context, host string) ([]net.IPAddr, error)
	LookupAddr(ctx context.Context, addr string) ([]string, error)
	LookupNS(ctx context.Context, name string) ([]*net.NS, error)
	LookupSOA(ctx context.Context, name string) (*SOA, error)
	LookupDNSSEC(ctx context.Context, name string) (DNSSECStatus, error)
}

type MetricsResolver interface {
	QueryMetrics() []QueryMetric
}

type NetResolver struct {
	resolver *net.Resolver
	dnsQuery func(ctx context.Context, name string, recordType uint16) (*DNSResponse, error)
	mu       sync.Mutex
	metrics  []QueryMetric
}

func NewNetResolver() *NetResolver {
	return &NetResolver{
		resolver: net.DefaultResolver,
		dnsQuery: defaultDNSQuery,
	}
}

func (r *NetResolver) LookupMX(ctx context.Context, domain string) ([]*net.MX, error) {
	start := time.Now()
	records, err := r.resolver.LookupMX(ctx, domain)
	r.recordMetric(domain, "MX", time.Since(start), err)
	return records, err
}

func (r *NetResolver) LookupTXT(ctx context.Context, name string) ([]string, error) {
	start := time.Now()
	records, err := r.resolver.LookupTXT(ctx, name)
	r.recordMetric(name, "TXT", time.Since(start), err)
	return records, err
}

func (r *NetResolver) LookupIPAddr(ctx context.Context, host string) ([]net.IPAddr, error) {
	start := time.Now()
	records, err := r.resolver.LookupIPAddr(ctx, host)
	r.recordMetric(host, "A/AAAA", time.Since(start), err)
	return records, err
}

func (r *NetResolver) LookupAddr(ctx context.Context, addr string) ([]string, error) {
	start := time.Now()
	names, err := r.resolver.LookupAddr(ctx, addr)
	r.recordMetric(addr, "PTR", time.Since(start), err)
	return names, err
}

func (r *NetResolver) LookupNS(ctx context.Context, name string) ([]*net.NS, error) {
	start := time.Now()
	records, err := r.resolver.LookupNS(ctx, name)
	r.recordMetric(name, "NS", time.Since(start), err)
	return records, err
}

func (r *NetResolver) LookupSOA(ctx context.Context, name string) (*SOA, error) {
	start := time.Now()
	response, err := r.queryDNS(ctx, name, TypeSOA)
	r.recordMetric(name, "SOA", time.Since(start), err)
	if err != nil {
		return nil, err
	}
	if response.SOA == nil {
		return nil, &net.DNSError{Err: "no SOA record found", Name: name, IsNotFound: true}
	}

	return response.SOA, nil
}

func (r *NetResolver) LookupDNSSEC(ctx context.Context, name string) (DNSSECStatus, error) {
	start := time.Now()
	response, err := r.queryDNS(ctx, name, TypeDNSKEY)
	r.recordMetric(name, "DNSSEC", time.Since(start), err)
	if err != nil {
		return DNSSECStatus{}, err
	}

	return DNSSECStatus{
		Validated: response.AuthenticatedData,
		Source:    "resolver AD bit",
	}, nil
}

func (r *NetResolver) queryDNS(ctx context.Context, name string, recordType uint16) (*DNSResponse, error) {
	query := r.dnsQuery
	if query == nil {
		query = defaultDNSQuery
	}

	return query(ctx, name, recordType)
}

func (r *NetResolver) QueryMetrics() []QueryMetric {
	r.mu.Lock()
	defer r.mu.Unlock()

	metrics := make([]QueryMetric, len(r.metrics))
	copy(metrics, r.metrics)
	return metrics
}

func (r *NetResolver) recordMetric(name string, recordType string, duration time.Duration, err error) {
	metric := QueryMetric{
		Name:       name,
		Type:       recordType,
		DurationMS: duration.Milliseconds(),
	}
	if err != nil {
		metric.Error = err.Error()
	}

	r.mu.Lock()
	defer r.mu.Unlock()
	r.metrics = append(r.metrics, metric)
}

func defaultDNSQuery(ctx context.Context, name string, recordType uint16) (*DNSResponse, error) {
	servers, err := configuredDNSServers()
	if err != nil {
		return nil, err
	}

	message := codedns.NewMsg(name, recordType)
	if message == nil {
		return nil, fmt.Errorf("unsupported DNS record type %d", recordType)
	}
	message.Security = true
	message.UDPSize = 1232

	client := codedns.NewClient()
	var lastErr error
	for _, server := range servers {
		response, _, err := client.Exchange(ctx, message, "udp", server)
		if err == nil {
			return dnsResponseFromMsg(response), nil
		}
		lastErr = err
	}

	if lastErr != nil {
		return nil, lastErr
	}

	return nil, ErrNoResolver
}

func configuredDNSServers() ([]string, error) {
	data, err := os.ReadFile("/etc/resolv.conf")
	if err != nil {
		return nil, err
	}

	servers := make([]string, 0, 2)
	for _, line := range strings.Split(string(data), "\n") {
		fields := strings.Fields(line)
		if len(fields) < 2 || fields[0] != "nameserver" {
			continue
		}

		servers = append(servers, net.JoinHostPort(fields[1], "53"))
	}
	if len(servers) == 0 {
		return nil, ErrNoResolver
	}

	return servers, nil
}

func dnsResponseFromMsg(message *codedns.Msg) *DNSResponse {
	response := &DNSResponse{AuthenticatedData: message.AuthenticatedData}
	for _, rr := range append(message.Answer, message.Ns...) {
		soa, ok := rr.(*codedns.SOA)
		if !ok {
			continue
		}

		response.SOA = &SOA{
			NS:      soa.Ns,
			MBox:    soa.Mbox,
			Serial:  soa.Serial,
			Refresh: soa.Refresh,
			Retry:   soa.Retry,
			Expire:  soa.Expire,
			MinTTL:  soa.Minttl,
		}
		break
	}

	return response
}
