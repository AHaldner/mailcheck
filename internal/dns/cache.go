package dns

import (
	"context"
	"net"
	"sync"
)

type cacheKey struct {
	recordType string
	name       string
}

type cacheResult struct {
	value any
	err   error
}

type cacheCall struct {
	done   chan struct{}
	result cacheResult
}

type CachedResolver struct {
	base    Resolver
	metrics MetricsResolver

	mu       sync.Mutex
	entries  map[cacheKey]cacheResult
	inflight map[cacheKey]*cacheCall
}

func NewCachedResolver(base Resolver) *CachedResolver {
	metrics, _ := base.(MetricsResolver)
	return &CachedResolver{
		base:     base,
		metrics:  metrics,
		entries:  make(map[cacheKey]cacheResult),
		inflight: make(map[cacheKey]*cacheCall),
	}
}

func (r *CachedResolver) LookupMX(ctx context.Context, domain string) ([]*net.MX, error) {
	value, err := r.lookup(ctx, cacheKey{recordType: "MX", name: domain}, func(ctx context.Context) (any, error) {
		records, err := r.base.LookupMX(ctx, domain)
		return cloneMX(records), err
	})
	if err != nil {
		return nil, err
	}

	return cloneMX(value.([]*net.MX)), nil
}

func (r *CachedResolver) LookupTXT(ctx context.Context, name string) ([]string, error) {
	value, err := r.lookup(ctx, cacheKey{recordType: "TXT", name: name}, func(ctx context.Context) (any, error) {
		records, err := r.base.LookupTXT(ctx, name)
		return cloneStrings(records), err
	})
	if err != nil {
		return nil, err
	}

	return cloneStrings(value.([]string)), nil
}

func (r *CachedResolver) LookupIPAddr(ctx context.Context, host string) ([]net.IPAddr, error) {
	value, err := r.lookup(ctx, cacheKey{recordType: "A/AAAA", name: host}, func(ctx context.Context) (any, error) {
		records, err := r.base.LookupIPAddr(ctx, host)
		return cloneIPAddrs(records), err
	})
	if err != nil {
		return nil, err
	}

	return cloneIPAddrs(value.([]net.IPAddr)), nil
}

func (r *CachedResolver) LookupAddr(ctx context.Context, addr string) ([]string, error) {
	value, err := r.lookup(ctx, cacheKey{recordType: "PTR", name: addr}, func(ctx context.Context) (any, error) {
		records, err := r.base.LookupAddr(ctx, addr)
		return cloneStrings(records), err
	})
	if err != nil {
		return nil, err
	}

	return cloneStrings(value.([]string)), nil
}

func (r *CachedResolver) LookupNS(ctx context.Context, name string) ([]*net.NS, error) {
	value, err := r.lookup(ctx, cacheKey{recordType: "NS", name: name}, func(ctx context.Context) (any, error) {
		records, err := r.base.LookupNS(ctx, name)
		return cloneNS(records), err
	})
	if err != nil {
		return nil, err
	}

	return cloneNS(value.([]*net.NS)), nil
}

func (r *CachedResolver) LookupSOA(ctx context.Context, name string) (*SOA, error) {
	value, err := r.lookup(ctx, cacheKey{recordType: "SOA", name: name}, func(ctx context.Context) (any, error) {
		record, err := r.base.LookupSOA(ctx, name)
		return cloneSOA(record), err
	})
	if err != nil {
		return nil, err
	}

	return cloneSOA(value.(*SOA)), nil
}

func (r *CachedResolver) LookupDNSSEC(ctx context.Context, name string) (DNSSECStatus, error) {
	value, err := r.lookup(ctx, cacheKey{recordType: "DNSSEC", name: name}, func(ctx context.Context) (any, error) {
		return r.base.LookupDNSSEC(ctx, name)
	})
	if err != nil {
		return DNSSECStatus{}, err
	}

	return value.(DNSSECStatus), nil
}

func (r *CachedResolver) QueryMetrics() []QueryMetric {
	if r.metrics == nil {
		return nil
	}

	return r.metrics.QueryMetrics()
}

func (r *CachedResolver) lookup(ctx context.Context, key cacheKey, load func(context.Context) (any, error)) (any, error) {
	r.mu.Lock()
	if result, ok := r.entries[key]; ok {
		r.mu.Unlock()
		return result.value, result.err
	}
	if call, ok := r.inflight[key]; ok {
		r.mu.Unlock()
		select {
		case <-call.done:
			return call.result.value, call.result.err
		case <-ctx.Done():
			return nil, ctx.Err()
		}
	}

	call := &cacheCall{done: make(chan struct{})}
	r.inflight[key] = call
	r.mu.Unlock()

	value, err := load(ctx)
	call.result = cacheResult{value: value, err: err}

	r.mu.Lock()
	r.entries[key] = call.result
	delete(r.inflight, key)
	r.mu.Unlock()
	close(call.done)

	return value, err
}

func cloneMX(records []*net.MX) []*net.MX {
	if records == nil {
		return nil
	}

	cloned := make([]*net.MX, len(records))
	for i, record := range records {
		if record == nil {
			continue
		}

		copyRecord := *record
		cloned[i] = &copyRecord
	}

	return cloned
}

func cloneNS(records []*net.NS) []*net.NS {
	if records == nil {
		return nil
	}

	cloned := make([]*net.NS, len(records))
	for i, record := range records {
		if record == nil {
			continue
		}

		copyRecord := *record
		cloned[i] = &copyRecord
	}

	return cloned
}

func cloneIPAddrs(records []net.IPAddr) []net.IPAddr {
	if records == nil {
		return nil
	}

	cloned := make([]net.IPAddr, len(records))
	for i, record := range records {
		cloned[i] = record
		if record.IP != nil {
			cloned[i].IP = append(net.IP(nil), record.IP...)
		}
	}

	return cloned
}

func cloneStrings(records []string) []string {
	if records == nil {
		return nil
	}

	cloned := make([]string, len(records))
	copy(cloned, records)
	return cloned
}

func cloneSOA(record *SOA) *SOA {
	if record == nil {
		return nil
	}

	cloned := *record
	return &cloned
}
