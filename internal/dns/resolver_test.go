package dns

import (
	"context"
	"net"
	"testing"
)

var _ Resolver = (*NetResolver)(nil)
var _ MetricsResolver = (*NetResolver)(nil)

func TestNewNetResolverUsesDefaultResolver(t *testing.T) {
	got := NewNetResolver()
	if got.resolver != net.DefaultResolver {
		t.Fatal("NewNetResolver() did not use net.DefaultResolver")
	}
}

func TestLookupSOAUsesDNSClient(t *testing.T) {
	r := NetResolver{
		resolver: net.DefaultResolver,
		dnsQuery: func(_ context.Context, name string, recordType uint16) (*DNSResponse, error) {
			if name != "example.com" {
				t.Fatalf("name = %q, want example.com", name)
			}
			if recordType != TypeSOA {
				t.Fatalf("recordType = %d, want SOA", recordType)
			}

			return &DNSResponse{
				SOA: &SOA{
					NS:     "ns1.example.com.",
					MBox:   "hostmaster.example.com.",
					Serial: 2026042401,
				},
			}, nil
		},
	}

	got, err := r.LookupSOA(context.Background(), "example.com")
	if err != nil {
		t.Fatalf("LookupSOA error = %v", err)
	}

	if got.NS != "ns1.example.com." || got.Serial != 2026042401 {
		t.Fatalf("SOA = %+v, want ns and serial", got)
	}
}

func TestLookupDNSSECUsesADBit(t *testing.T) {
	r := NetResolver{
		resolver: net.DefaultResolver,
		dnsQuery: func(_ context.Context, _ string, recordType uint16) (*DNSResponse, error) {
			if recordType != TypeDNSKEY {
				t.Fatalf("recordType = %d, want DNSKEY", recordType)
			}

			return &DNSResponse{AuthenticatedData: true}, nil
		},
	}

	got, err := r.LookupDNSSEC(context.Background(), "example.com")
	if err != nil {
		t.Fatalf("LookupDNSSEC error = %v", err)
	}

	if !got.Validated {
		t.Fatalf("Validated = false, want true")
	}
}
