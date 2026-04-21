package dns

import (
	"context"
	"net"
)

type Resolver interface {
	LookupMX(ctx context.Context, domain string) ([]*net.MX, error)
	LookupTXT(ctx context.Context, name string) ([]string, error)
}

type NetResolver struct {
	resolver *net.Resolver
}

func NewNetResolver() NetResolver {
	return NetResolver{resolver: net.DefaultResolver}
}

func (r NetResolver) LookupMX(ctx context.Context, domain string) ([]*net.MX, error) {
	return r.resolver.LookupMX(ctx, domain)
}

func (r NetResolver) LookupTXT(ctx context.Context, name string) ([]string, error) {
	return r.resolver.LookupTXT(ctx, name)
}
