package scanners

import (
	"context"
	"math/rand/v2"
	"time"
)

type TCPScanner struct {
	// dialer *net.Dialer

	// configuration fields if needed
}

// This scanner performs TCP connection attempt
func NewTCPScanner() *TCPScanner {
	return &TCPScanner{}
}

func (s *TCPScanner) GetName() string {
	return "TCP Scan"
}

func (s *TCPScanner) ScanTimeout(ctx context.Context, target *TargetInfo, timeout time.Duration) error {
	select {
	case <-ctx.Done():
		return ctx.Err()
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
	}
	return nil
}

// TODO fingerprint target
// TODO banner grabbing
