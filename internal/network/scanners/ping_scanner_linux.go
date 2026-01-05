package scanners

import (
	"context"
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

func (s *PingScanner) ScanTimeout(ctx context.Context, target *TargetInfo, timeout time.Duration) error {
	select {
	case <-ctx.Done():
		return ctx.Err()
	default:
		// TODO actual implementation here
		// https://pkg.go.dev/golang.org/x/net/icmp#example-PacketConn-NonPrivilegedPing
	}
	return nil
}
