package scanners

import (
	"context"
	"fmt"
	"math/rand/v2"
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
		target.Comments = append(target.Comments,
			fmt.Sprintf("%s interrupted by context", s.GetName()))
		return ctx.Err()
	default:
		// TODO actual implementation here with ICMP echo
		time.Sleep(time.Duration((rand.IntN(900) + 100)) * time.Millisecond)
		target.Comments = append(target.Comments,
			fmt.Sprintf("scanned by %s", s.GetName()))
	}
	return nil
}
