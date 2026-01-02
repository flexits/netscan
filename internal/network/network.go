package network

import (
	"net/netip"
)

func ParseCidrOrAddr(s string) (*netip.Prefix, error) {
	prefix, err := netip.ParsePrefix(s)
	if err != nil {
		// maybe it's a single IP address without a mask
		ip, err2 := netip.ParseAddr(s)
		if err2 != nil {
			return nil, err
		}
		prefix = netip.PrefixFrom(ip, ip.BitLen())
	}
	prefix = prefix.Masked()
	return &prefix, nil
	// TODO we return prefix and then convert it to a hosts list;
	// but in case of individual address, we may return a single-item list right away
}

func HostsInPrefix(prefix *netip.Prefix) *[]netip.Addr {
	var hosts []netip.Addr
	// TODO consider this https://pkg.go.dev/github.com/projectdiscovery/mapcidr
	// or use bit-manipulation to calculate addresses in the range
	/*
		start := prefix.Addr().Next()
		end := prefix.Broadcast().Prev()

		for ip := start; ip <= end; ip = ip.Next() {
			hosts = append(hosts, ip)
		}
	*/
	return &hosts
}
