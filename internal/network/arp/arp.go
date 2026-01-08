package arp

import (
	"net/netip"
	"strings"
)

type ArpInfo struct {
	Ip  netip.Addr
	Mac string
}

type ArpTableValue struct {
	Mac         string
	IsProcessed bool
}

func GetArpTable() (map[netip.Addr]*ArpTableValue, error) {
	values, err := RetrieveArpTable()
	if err != nil {
		return nil, nil
	}
	result := make(map[netip.Addr]*ArpTableValue)
	for _, v := range values {
		if isNonUnicastMac(v.Mac) {
			continue
		}
		result[v.Ip] = &ArpTableValue{
			Mac:         v.Mac,
			IsProcessed: false,
		}
	}
	return result, nil
}

var (
	broadcastMac = "ff:ff:ff:ff:ff:ff"
	multicastMac = "01:00:5e"
)

// Check if provided mac is
// broadcast, multicast or
// is shorter than 17 bytes.
func isNonUnicastMac(mac string) bool {
	if len(mac) < 17 {
		return true
	}
	if strings.EqualFold(mac[:8], multicastMac) {
		return true
	}
	return strings.EqualFold(mac, broadcastMac)
}
