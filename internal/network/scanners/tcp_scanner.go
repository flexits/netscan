package scanners

import (
	"context"
	"fmt"
	"time"
)

type TCPScanner struct {
	// configuration fields if needed
}

func (s *TCPScanner) Name() string {
	return "TCP Scanner"
}

func (s *TCPScanner) Scan(ctx context.Context, target *Target) (ScanResult, error) {
	result := ScanResult{
		ScannerName: s.Name(),
		Status:      "scanned",
	}
	select {
	case <-ctx.Done():
		result.Status = "interrupted"
		return result, ctx.Err()
	default:
		// TODO actual implementation here with Dialer.DialContext
		// ... reuse dialer with KeepAlive disabled ...
		time.Sleep(1 * time.Second)
		result.Status = fmt.Sprintf("Scanned %s", target.Address.String())
	}
	return result, nil
}
