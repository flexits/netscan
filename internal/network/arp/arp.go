package arp

import (
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
		// TODO move broadcast MAC detection here
		result[v.Ip] = &ArpTableValue{
			Mac:         v.Mac,
			IsProcessed: false,
		}
	}
	return result, nil
}

var broadcastMacBytes = []byte{0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF}
