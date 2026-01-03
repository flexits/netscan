package network

import (
	"net/netip"
)

type AddrParser struct {
	isVerbose bool // TODO verbosity is not implemented yet
}

// AddrParser performs parsing of CIDR notation or single IP address string.
func NewAddrParser() *AddrParser {
	return &AddrParser{}
}

func (p *AddrParser) SetVerbosity(on bool) {
	p.isVerbose = on
}

// Parses CIDR notation or single IP address string.
//
// Returns:
//   - pointer to the slice with parsed addresses or nil on error;
//   - error value or nil on success.
func (p *AddrParser) ParseCidrOrAddr(s string) (*[]netip.Addr, error) {
	prefix, err := netip.ParsePrefix(s)
	if err != nil {
		// maybe it's a single IP address without a mask
		ip, err2 := netip.ParseAddr(s)
		if err2 != nil {
			return nil, err
		}
		return &[]netip.Addr{ip}, nil
	}
	// it's a CIDR range
	return p.populateHosts(prefix.Masked())
}

func (p *AddrParser) populateHosts(prefix netip.Prefix) (*[]netip.Addr, error) {
	// TODO generate list of addresses contained in the given prefix
	// excluding self and broadcast addresses
	hosts := []netip.Addr{}
	// consider this https://pkg.go.dev/github.com/projectdiscovery/mapcidr
	// or use bit-manipulation to calculate addresses in the range
	/*
		start := prefix.Addr().Next()
		end := prefix.Broadcast().Prev()

		for ip := start; ip <= end; ip = ip.Next() {
			hosts = append(hosts, ip)
		}
	*/
	return &hosts, nil
}
