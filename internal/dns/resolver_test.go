package dns

import (
	"net"
	"testing"
)

var _ Resolver = NetResolver{}

func TestNewNetResolverUsesDefaultResolver(t *testing.T) {
	got := NewNetResolver()
	if got.resolver != net.DefaultResolver {
		t.Fatal("NewNetResolver() did not use net.DefaultResolver")
	}
}
