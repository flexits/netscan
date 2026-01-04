package scanners

import (
	"context"
	"fmt"
	"math/rand/v2"
	"net/netip"
	"time"
)

type PingScanner struct {
	// configuration fields if needed
}

// This scanner performs ping (ICMP echo) scan
func NewPingScanner() *PingScanner {
	return &PingScanner{}
}

func (s *PingScanner) GetName() string {
	return "ICMP Ping"
}

func (s *PingScanner) Scan(ctx context.Context, addr netip.Addr) (*ScanResult, error) {
	result := &ScanResult{
		ScannerName: s.GetName(),
		Status:      "scanned",
	}
	select {
	case <-ctx.Done():
		result.Status = "interrupted"
		return result, ctx.Err()
	default:
		// TODO actual implementation here with ICMP echo
		time.Sleep(time.Duration((rand.IntN(900) + 100)) * time.Millisecond)
		result.Status = fmt.Sprintf("Scanned %s", addr.String())
	}
	return result, nil
}
