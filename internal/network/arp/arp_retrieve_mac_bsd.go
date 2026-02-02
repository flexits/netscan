//go:build darwin || freebsd || netbsd || openbsd

/*
This code is derived from
[goarp](https://github.com/juruen/goarp/blob/master/arp/arp_bsd.go).
Original copyright (c) 2018 Javier Uruen Val
Licensed under MIT License

MIT License

Permission is hereby granted, free of charge, to any person obtaining a copy
of this software and associated documentation files (the "Software"), to deal
in the Software without restriction, including without limitation the rights
to use, copy, modify, merge, publish, distribute, sublicense, and/or sell
copies of the Software, and to permit persons to whom the Software is
furnished to do so, subject to the following conditions:

The above copyright notice and this permission notice shall be included in all
copies or substantial portions of the Software.

THE SOFTWARE IS PROVIDED "AS IS", WITHOUT WARRANTY OF ANY KIND, EXPRESS OR
IMPLIED, INCLUDING BUT NOT LIMITED TO THE WARRANTIES OF MERCHANTABILITY,
FITNESS FOR A PARTICULAR PURPOSE AND NONINFRINGEMENT. IN NO EVENT SHALL THE
AUTHORS OR COPYRIGHT HOLDERS BE LIABLE FOR ANY CLAIM, DAMAGES OR OTHER
LIABILITY, WHETHER IN AN ACTION OF CONTRACT, TORT OR OTHERWISE, ARISING FROM,
OUT OF OR IN CONNECTION WITH THE SOFTWARE OR THE USE OR OTHER DEALINGS IN THE
SOFTWARE.
*/

package arp

import (
	"fmt"
	"net"
	"net/netip"
	"syscall"
	"unsafe"
)

// Loads the system ARP table via syscall,
// parses the contents and returns a slice of
// IP - MAC pairs, or (nil, error) in case of an error.
func RetrieveArpTable() ([]ArpInfo, error) {
	buf, err := dumpArpTableSyscall()

	if err != nil {
		return nil, err
	}

	return parseArpTable(buf)
}

type sockaddrInArp struct {
	len    uint8
	family uint8
	port   uint16
	addr   [4]byte
}

// Invokes native BSD sycall to
// fetch routing and link layer information.
func dumpArpTableSyscall() ([]byte, error) {
	mib := [6]int32{
		syscall.CTL_NET,
		syscall.AF_ROUTE,
		0,
		syscall.AF_INET,
		syscall.NET_RT_FLAGS,
		syscall.RTF_LLINFO,
	}

	size := uintptr(0)

	_, _, errno := syscall.Syscall6(
		syscall.SYS___SYSCTL,
		uintptr(unsafe.Pointer(&mib[0])),
		6,
		0,
		uintptr(unsafe.Pointer(&size)),
		0,
		0)

	if errno != 0 {
		return nil, errno
	}

	if size == 0 {
		return nil, nil // empty table
	}

	var bs []byte
	for {
		bs = make([]byte, size)
		_, _, errno := syscall.Syscall6(
			syscall.SYS___SYSCTL,
			uintptr(unsafe.Pointer(&mib[0])),
			6,
			uintptr(unsafe.Pointer(&bs[0])),
			uintptr(unsafe.Pointer(&size)),
			0,
			0)

		if errno == syscall.ENOMEM {
			continue
		}

		if errno == 0 {
			break
		}

		return nil, errno
	}

	return bs, nil
}

// Parses the raw buffer returned by syscall.
func parseArpTable(buf []byte) ([]ArpInfo, error) {
	table := make([]ArpInfo, 0)

	offset := 0
	for offset < len(buf) {
		header := (*syscall.RtMsghdr)(unsafe.Pointer(&buf[offset]))
		ipAddrPtr := offset + syscall.SizeofRtMsghdr
		offset += int(header.Msglen)

		ipAddr := (*sockaddrInArp)(unsafe.Pointer(&buf[ipAddrPtr]))
		if ipAddr.family != syscall.AF_INET {
			continue
		}
		ip := netip.AddrFrom4(ipAddr.addr)

		datalinkPtr := ipAddrPtr + int(ipAddr.len)
		datalink := (*syscall.SockaddrDatalink)(unsafe.Pointer(&buf[datalinkPtr]))
		if datalink.Alen < 6 {
			continue
		}

		macStr := fmt.Sprintf("%02x:%02x:%02x:%02x:%02x:%02x",
			byte(datalink.Data[0]),
			byte(datalink.Data[1]),
			byte(datalink.Data[2]),
			byte(datalink.Data[3]),
			byte(datalink.Data[4]),
			byte(datalink.Data[5]),
		)
		mac, err := net.ParseMAC(macStr)
		if err != nil {
			continue
		}
		if isNonUnicastMac(mac) {
			continue
		}
		table = append(table, ArpInfo{Ip: ip, Mac: macStr})
	}

	return table, nil
}
