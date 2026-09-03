package security

import (
	"context"
	"crypto/tls"
	"fmt"
	"net"
	"net/http"
	"net/netip"
	"net/url"
	"strings"
	"time"
)

type NetworkPolicy struct {
	Allowed  []netip.Prefix
	Resolver *net.Resolver
}

func NewNetworkPolicy(cidrs []string) (*NetworkPolicy, error) {
	p := &NetworkPolicy{Resolver: net.DefaultResolver}
	for _, s := range cidrs {
		v, e := netip.ParsePrefix(strings.TrimSpace(s))
		if e != nil {
			return nil, e
		}
		p.Allowed = append(p.Allowed, v)
	}
	return p, nil
}
func (p *NetworkPolicy) AllowedIP(ip netip.Addr) bool {
	ip = ip.Unmap()
	if !ip.IsValid() || ip.IsUnspecified() || ip.IsMulticast() || ip.IsLinkLocalUnicast() || ip.IsLinkLocalMulticast() {
		return false
	}
	for _, prefix := range p.Allowed {
		if prefix.Contains(ip) {
			return true
		}
	}
	return false
}
func (p *NetworkPolicy) Resolve(ctx context.Context, host string) ([]netip.Addr, error) {
	ips, e := p.Resolver.LookupNetIP(ctx, "ip", host)
	if e != nil {
		return nil, e
	}
	if len(ips) == 0 {
		return nil, fmt.Errorf("no address")
	}
	for _, ip := range ips {
		if !p.AllowedIP(ip) {
			return nil, fmt.Errorf("destination outside OUTBOUND_ALLOWED_CIDRS")
		}
	}
	return ips, nil
}
func (p *NetworkPolicy) DialContext(ctx context.Context, network, address string) (net.Conn, error) {
	host, port, e := net.SplitHostPort(address)
	if e != nil {
		return nil, e
	}
	ips, e := p.Resolve(ctx, host)
	if e != nil {
		return nil, e
	}
	d := net.Dialer{Timeout: 10 * time.Second}
	var last error
	for _, ip := range ips {
		c, e := d.DialContext(ctx, network, net.JoinHostPort(ip.String(), port))
		if e == nil {
			return c, nil
		}
		last = e
	}
	return nil, last
}
func (p *NetworkPolicy) ValidateURL(raw string) error {
	u, e := url.Parse(raw)
	if e != nil || u.Hostname() == "" || u.User != nil || u.Fragment != "" || (u.Scheme != "https" && u.Scheme != "http") {
		return fmt.Errorf("invalid endpoint URL")
	}
	return nil
}
func (p *NetworkPolicy) Client(timeout time.Duration) *http.Client {
	return &http.Client{Timeout: timeout, Transport: &http.Transport{DialContext: p.DialContext, TLSClientConfig: &tls.Config{MinVersion: tls.VersionTLS12}, MaxIdleConns: 10, IdleConnTimeout: 30 * time.Second, ResponseHeaderTimeout: timeout}, CheckRedirect: func(_ *http.Request, _ []*http.Request) error { return fmt.Errorf("redirects forbidden") }}
}
