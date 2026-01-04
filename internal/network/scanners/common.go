package scanners

import (
	"context"
	"net/netip"
)

type ScanResult struct {
	ScannerName string
	Status      string
	Mac         string
	HostName    string
	// something else...
}

type Target struct {
	Address netip.Addr
	Results []*ScanResult
	// something else...
}

type Scanner interface {
	Scan(ctx context.Context, addr netip.Addr) (*ScanResult, error)
	Name() string
}
