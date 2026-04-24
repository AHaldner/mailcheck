package dns

import (
	"context"
	"net"
	"sync"
	"testing"
)

func TestCachedResolverReusesDuplicateLookups(t *testing.T) {
	base := &countingResolver{
		mx:  []*net.MX{{Host: "mx.example.com.", Pref: 10}},
		txt: []string{"v=spf1 -all"},
		ips: []net.IPAddr{{IP: net.ParseIP("192.0.2.10")}},
	}
	resolver := NewCachedResolver(base)

	for range 2 {
		mx, err := resolver.LookupMX(context.Background(), "example.com")
		if err != nil {
			t.Fatalf("LookupMX error = %v", err)
		}
		mx[0].Host = "mutated.example.com."

		txt, err := resolver.LookupTXT(context.Background(), "example.com")
		if err != nil {
			t.Fatalf("LookupTXT error = %v", err)
		}
		txt[0] = "mutated"

		ips, err := resolver.LookupIPAddr(context.Background(), "mx.example.com.")
		if err != nil {
			t.Fatalf("LookupIPAddr error = %v", err)
		}
		ips[0].IP[0] = 203
	}

	if base.mxCalls != 1 {
		t.Fatalf("LookupMX calls = %d, want 1", base.mxCalls)
	}
	if base.txtCalls != 1 {
		t.Fatalf("LookupTXT calls = %d, want 1", base.txtCalls)
	}
	if base.ipCalls != 1 {
		t.Fatalf("LookupIPAddr calls = %d, want 1", base.ipCalls)
	}

	mx, err := resolver.LookupMX(context.Background(), "example.com")
	if err != nil {
		t.Fatalf("LookupMX error = %v", err)
	}
	if mx[0].Host != "mx.example.com." {
		t.Fatalf("cached MX was mutated: %q", mx[0].Host)
	}

	txt, err := resolver.LookupTXT(context.Background(), "example.com")
	if err != nil {
		t.Fatalf("LookupTXT error = %v", err)
	}
	if txt[0] != "v=spf1 -all" {
		t.Fatalf("cached TXT was mutated: %q", txt[0])
	}

	ips, err := resolver.LookupIPAddr(context.Background(), "mx.example.com.")
	if err != nil {
		t.Fatalf("LookupIPAddr error = %v", err)
	}
	if !ips[0].IP.Equal(net.ParseIP("192.0.2.10")) {
		t.Fatalf("cached IP was mutated: %s", ips[0].IP)
	}
}

type countingResolver struct {
	mu       sync.Mutex
	mx       []*net.MX
	txt      []string
	ips      []net.IPAddr
	mxCalls  int
	txtCalls int
	ipCalls  int
}

func (r *countingResolver) LookupMX(context.Context, string) ([]*net.MX, error) {
	r.mu.Lock()
	defer r.mu.Unlock()
	r.mxCalls++
	return cloneMX(r.mx), nil
}

func (r *countingResolver) LookupTXT(context.Context, string) ([]string, error) {
	r.mu.Lock()
	defer r.mu.Unlock()
	r.txtCalls++
	return cloneStrings(r.txt), nil
}

func (r *countingResolver) LookupIPAddr(context.Context, string) ([]net.IPAddr, error) {
	r.mu.Lock()
	defer r.mu.Unlock()
	r.ipCalls++
	return cloneIPAddrs(r.ips), nil
}

func (*countingResolver) LookupAddr(context.Context, string) ([]string, error) {
	return nil, nil
}

func (*countingResolver) LookupNS(context.Context, string) ([]*net.NS, error) {
	return nil, nil
}

func (*countingResolver) LookupSOA(context.Context, string) (*SOA, error) {
	return nil, nil
}

func (*countingResolver) LookupDNSSEC(context.Context, string) (DNSSECStatus, error) {
	return DNSSECStatus{}, nil
}
