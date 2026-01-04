package scanners

import (
	"context"
	"net"
	"strings"
	"time"
)

type TCPScanner struct {
	dialer *net.Dialer
	ports  []string
	// configuration fields if needed
}

// This scanner performs TCP connection attempt
func NewTCPScanner() *TCPScanner {
	return &TCPScanner{
		dialer: &net.Dialer{
			KeepAlive: -1,
		},
		ports: []string{"80", "443", "22", "445", "3389"},
	}
}

func (s *TCPScanner) GetName() string {
	return "TCP Scan"
}

func (s *TCPScanner) ScanTimeout(ctx context.Context, target *TargetInfo, timeout time.Duration) error {
	select {
	case <-ctx.Done():
		return ctx.Err()
	default:
		for _, port := range s.ports {
			context, cancel := context.WithTimeout(ctx, timeout)
			defer cancel()
			addr := net.JoinHostPort(target.Address.String(), port)
			conn, err := s.dialer.DialContext(context, "tcp", addr)
			if err != nil {
				errStr := err.Error()
				// possible strings:
				// i/o timeout
				// connect: host is down
				// connect: no route to host
				//
				// positive detection:
				// connect: connection refused
				// target.Comments = append(target.Comments, errStr)
				/*
					switch {
					case strings.Contains(errStr, "refused"):
						target.SetState(HostAlive)
					// case strings.Contains(errStr, "timeout"): target.SetState(HostUnknown)
					case strings.Contains(errStr, "no route") ||
						strings.Contains(errStr, "down") ||
						strings.Contains(errStr, "unreachable"):
						target.SetState(HostDead)
					default:
						target.SetState(HostUnknown)
					}
				*/
				if strings.Contains(errStr, "refused") {
					target.SetState(HostAlive)
					break
				}
			} else {
				// TODO fingerprint target
				// TODO banner grabbing
				conn.Close()
				target.SetState(HostAlive)
				break
			}
			/*
				if target.GetState() == HostAlive {
					break
				}
			*/
		}
	}
	return nil
}
