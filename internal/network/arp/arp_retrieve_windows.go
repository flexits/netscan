package arp

import (
	"net"
	"net/netip"
	"os/exec"
	"strings"
)

/*
Example "arp -a" output:

Interface: 192.168.0.50 --- 0x11
  Internet Address      Physical Address      Type
  192.168.0.10          18-0f-76-00-00-00     dynamic
  192.168.0.11          40-cb-c0-00-00-00     dynamic
  192.168.0.13          2e-9e-6f-00-00-00     dynamic
  192.168.0.14          be-f9-6e-00-00-00     dynamic
  192.168.0.22          20-50-e7-00-00-00     dynamic
  192.168.0.23          b6-ed-a5-00-00-00     dynamic
  192.168.0.24          02-d4-26-00-00-00     dynamic
  192.168.0.25          9a-6b-f3-00-00-00     dynamic
  192.168.0.26          70-c9-32-00-00-00     dynamic
  192.168.0.255         ff-ff-ff-ff-ff-ff     static
  224.0.0.2             01-00-5e-00-00-02     static
  224.0.0.22            01-00-5e-00-00-16     static

Interface: 192.168.19.1 --- 0xf
  Internet Address      Physical Address      Type
  192.168.19.255        ff-ff-ff-ff-ff-ff     static
  224.0.0.2             01-00-5e-00-00-02     static

We can't rely on "Type" column because it's language-dependent!
*/

// Parses the "arp -a" output
// and returns a slice of IP - MAC pairs
// or (nil, error) in case of an error.
func RetrieveArpTable() ([]ArpInfo, error) {
	data, err := exec.Command("arp", "-a").Output()
	if err != nil {
		return nil, err
	}

	table := make([]ArpInfo, 0)
	for l := range strings.Lines(string(data)) {
		if len(l) < 24 {
			continue
		}
		tokens := strings.Fields(l)
		if len(tokens) != 3 {
			continue
		}
		ip, err := netip.ParseAddr(tokens[0])
		if err != nil {
			continue
		}
		mac, err := net.ParseMAC(tokens[1])
		if err != nil {
			continue
		}
		table = append(table, ArpInfo{Ip: ip, Mac: mac.String()})
	}
	return table, nil
}
