package arp

import (
	"bufio"
	"net"
	"net/netip"
	"os"
	"strings"
)

/*
Example "/proc/net/arp" contents:

IP address       HW type     Flags       HW address            Mask     Device
192.168.0.12     0x1         0x2         1a:90:05:00:01:02     *        enp3s0
192.168.0.15     0x1         0x2         c6:c4:d3:00:01:02     *        enp3s0
*/

// Parses the ARP table at /proc/net/arp
// and returns a slice of IP - MAC pairs
// or (nil, error) in case of an error.
func RetrieveArpTable() ([]ArpInfo, error) {

	f, err := os.Open("/proc/net/arp")
	if err != nil {
		return nil, err
	}
	defer f.Close()

	table := make([]ArpInfo, 0)
	scanner := bufio.NewScanner(f)
	for scanner.Scan() {
		l := scanner.Text()
		tokens := strings.Fields(l)
		if len(tokens) < 4 {
			continue
		}
		ip, err := netip.ParseAddr(tokens[0])
		if err != nil {
			continue
		}
		mac, err := net.ParseMAC(tokens[3])
		if err != nil {
			continue
		}
		if isNonUnicastMac(mac) {
			continue
		}
		table = append(table, ArpInfo{Ip: ip, Mac: mac.String()})
	}
	return table, nil
}
