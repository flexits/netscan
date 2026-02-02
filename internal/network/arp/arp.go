package arp

import (
	"net"
	"net/netip"
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
		result[v.Ip] = &ArpTableValue{
			Mac:         v.Mac,
			IsProcessed: false,
		}
	}
	return result, nil
}

// Check if provided mac is non-unicast
func isNonUnicastMac(mac net.HardwareAddr) bool {
	return (mac[0] & 1) == 1
}
