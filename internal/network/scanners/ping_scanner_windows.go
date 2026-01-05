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
		if !target.Address.Is4() {
			// TODO implement IPv6
			return errors.New("IPv6 ping not implemented")
		}
		h, _, err := procIcmpCreateFile.Call()
		if h == 0 {
			//fmt.Printf("Error in procIcmpCreateFile: %s\n", err.Error())
			return err
		}
		defer procIcmpCloseHandle.Call(h)
		payload := []byte("HELLO-R-U-THERE")
		//replySize := 3 * (unsafe.Sizeof(icmpEchoReply{}) + uintptr(len(payload)+64))
		replySize := 1024
		replyBuf := make([]byte, replySize) // TODO sync.Pool
		ip4 := target.Address.As4()
		ip := uint32(ip4[0])<<24 |
			uint32(ip4[1])<<16 |
			uint32(ip4[2])<<8 |
			uint32(ip4[3])
		//fmt.Println(ip)

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
			uintptr(timeout.Milliseconds()),
		)

		if r == 0 {
			//errno := windows.GetLastError()
			//fmt.Printf("Error in procIcmpSendEcho2 on %v: errno %v; err %s\n", ip4, errno, err)
			return err
		}

		reply := (*icmpEchoReply)(unsafe.Pointer(&replyBuf[0]))
		//fmt.Printf("Reply status: %d of %v\n", reply.Status, addrFromUint32(reply.Address))
		/*
			if reply.Data != nil {
				fmt.Printf("Reply data: %d\n", *reply.Data)
			}
			if reply.Options.OptionsData != nil {
				fmt.Printf("Reply options data: %d\n", *reply.Options.OptionsData)
			}
			if reply.Status != 0 {
				return fmt.Errorf("icmp status %d", reply.Status)
			}
			fmt.Println(reply)
		*/
		target.state = HostAlive
		target.Comments = append(target.Comments,
			fmt.Sprintf("ICMP Echo Responses = %d\n", r))
		target.Comments = append(target.Comments,
			fmt.Sprintf("Reply status: %d of %v\n", reply.Status, addrFromUint32(reply.Address)))
		return nil
	}
}

func addrFromUint32(u uint32) netip.Addr {
	b := [4]byte{
		byte(u >> 24),
		byte(u >> 16),
		byte(u >> 8),
		byte(u),
	}
	return netip.AddrFrom4(b)
}
