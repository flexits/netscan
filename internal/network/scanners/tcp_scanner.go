package scanners

import (
	"context"
	"fmt"
	"math/rand/v2"
	"net/netip"
	"time"
)

type TCPScanner struct {
	// dialer *net.Dialer

	// configuration fields if needed
}

func NewTCPScanner() *TCPScanner {
	return &TCPScanner{}
}

func (s *TCPScanner) GetName() string {
	return "TCP Scan"
}

func (s *TCPScanner) Scan(ctx context.Context, addr netip.Addr) (*ScanResult, error) {
	result := &ScanResult{
		ScannerName: s.GetName(),
		Status:      "scanned",
	}
	select {
	case <-ctx.Done():
		result.Status = "interrupted"
		return result, ctx.Err()
	default:
		// TODO actual implementation here with Dialer.DialContext
		/*
			if s.dialer == nil {
				s.dialer = &net.Dialer{
					Timeout:   s.Timeout,
					KeepAlive: -1,
				}
			}
		*/
		// ... reuse dialer with KeepAlive disabled ...
		time.Sleep(time.Duration((rand.IntN(900) + 100)) * time.Millisecond)
		result.Status = fmt.Sprintf("Scanned %s", addr.String())
	}
	return result, nil
}
