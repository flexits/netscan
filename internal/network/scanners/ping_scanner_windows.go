package scanners

import (
	"context"
	"errors"
	"fmt"
	"net/netip"
	"time"
	"unsafe"

	"golang.org/x/sys/windows"
)

type iPOptionInformation struct {
	Ttl         uint8
	Tos         uint8
	Flags       uint8
	OptionsSize uint8
	OptionsData *byte
}

type icmpEchoReply struct {
	Address       uint32
	Status        uint32
	RoundTripTime uint32
	DataSize      uint16
	Reserved      uint16
	Data          *byte
	Options       iPOptionInformation
}

var (
	modIphlpapi = windows.NewLazySystemDLL("iphlpapi.dll")

	procIcmpCreateFile  = modIphlpapi.NewProc("IcmpCreateFile")
	procIcmpCloseHandle = modIphlpapi.NewProc("IcmpCloseHandle")
	procIcmpSendEcho2   = modIphlpapi.NewProc("IcmpSendEcho2")
)

type PingScanner struct{}

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
		if !target.Address.Is4() {
			// TODO implement IPv6 with Icmp6SendEcho2
			return errors.New("IPv6 ping not implemented")
		}
		h, _, err := procIcmpCreateFile.Call()
		if h == 0 {
			return err
		}
		defer procIcmpCloseHandle.Call(h)

		payload := []byte("HELLO-R-U-THERE")

		replySize := 256
		replyBuf := make([]byte, replySize) // TODO sync.Pool

		ip := uint32FromAddr(target.Address)

		r, _, err := procIcmpSendEcho2.Call(
			h,
			0,
			0,
			0,
			uintptr(ip),
			uintptr(unsafe.Pointer(&payload[0])),
			uintptr(len(payload)),
			0,
			uintptr(unsafe.Pointer(&replyBuf[0])),
			uintptr(replySize),
			uintptr(3000),
		)
		if r == 0 {
			return err
		}

		reply := (*icmpEchoReply)(unsafe.Pointer(&replyBuf[0]))
		if reply.Status == 0 {
			// ping succeeded
			target.state = HostAlive
			target.Comments = append(target.Comments,
				fmt.Sprintf("ICMP Echo RTT %d ms", reply.RoundTripTime))
		}

		return nil
	}
}

// Convert uint32, compatible with IN_ADDR struct, into netip.Addr
func addrFromUint32(u uint32) netip.Addr {
	b := [4]byte{
		byte(u),
		byte(u >> 8),
		byte(u >> 16),
		byte(u >> 24),
	}
	return netip.AddrFrom4(b)
}

// Convert IPv4 netip.Addr into uint32, compatible with IN_ADDR struct
func uint32FromAddr(a netip.Addr) uint32 {
	ip4 := a.As4()
	return uint32(ip4[3])<<24 |
		uint32(ip4[2])<<16 |
		uint32(ip4[1])<<8 |
		uint32(ip4[0])
}
