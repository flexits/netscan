package scanners

import (
	"context"
	"net/netip"
)

// Result of a distinct scan
type ScanResult struct {
	ScannerName string
	Status      string
	Mac         string
	HostName    string
	// something else...
}

// Scanned host information, including various scanners results
type Target struct {
	Address netip.Addr
	Results []*ScanResult
	// something else...
}

// Unified interface for all scanners
type Scanner interface {
	Scan(ctx context.Context, addr netip.Addr) (*ScanResult, error)
	GetName() string
}
