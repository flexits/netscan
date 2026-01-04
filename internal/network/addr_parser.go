package network

import (
	"errors"
	"iter"
	"net"
	"net/netip"
)

type AddrParser struct {
	hostsFirst netip.Addr
	hostsLast  netip.Addr
	cidr       netip.Prefix
	isVerbose  bool // TODO verbosity is not implemented yet
}

// AddrParser performs parsing of CIDR notation or single IP address string.
func NewAddrParser() *AddrParser {
	return &AddrParser{}
}

func (p *AddrParser) SetVerbosity(on bool) {
	p.isVerbose = on
}

// Get first host address in the parsed range.
func (p *AddrParser) GetHostsFirst() netip.Addr {
	return p.hostsFirst
}

// Get last host address in the parsed range.
func (p *AddrParser) GetHostsLast() netip.Addr {
	return p.hostsLast
}

// Get CIDR prefix of the parsed range.
func (p *AddrParser) GetCIDR() netip.Prefix {
	return p.cidr
}

// Iterates over all host addresses in the parsed range,
// excluding network and broadcast addresses for IPv4.
func (p *AddrParser) Hosts() iter.Seq[netip.Addr] {
	return func(yield func(netip.Addr) bool) {
		for addr := p.hostsFirst; addr.IsValid(); addr = addr.Next() {
			if !yield(addr) {
				return
			}
			if addr == p.hostsLast {
				return
			}
		}
	}
}

// Parses CIDR notation or single IP address string.
// Populates hostsFirst and hostsLast fields.
//
// Returns:
//   - error value or nil on success.
func (p *AddrParser) ParseCidrOrAddr(s string) error {
	prefix, err := netip.ParsePrefix(s)
	if err != nil {
		// maybe it's a single IP address without a mask
		ip, err2 := netip.ParseAddr(s)
		if err2 != nil {
			return err
		}
		p.hostsFirst = ip
		p.hostsLast = ip
		p.cidr = netip.PrefixFrom(ip, ip.BitLen())
		return nil
	}
	// it's a CIDR range
	prefix = prefix.Masked()
	p.cidr = prefix
	return p.populateHosts()
}

func (p *AddrParser) populateHosts() error {
	network := p.cidr.Addr()
	if !network.IsValid() {
		return errors.New("invalid start address")
	}
	bits := p.cidr.Bits()
	if bits == 32 || bits == 128 {
		// single address
		p.hostsFirst = network
		p.hostsLast = network
		return nil
	}
	next := network.Next()
	if !next.IsValid() {
		return errors.New("failed to calculate next address")
	}
	if bits == 31 || bits == 127 {
		// two addresses only; no broadcast for IPv4
		p.hostsFirst = network
		p.hostsLast = next
		return nil
	}
	// larger networks
	last, err := calculateLastHostInRange(p.cidr)
	if err != nil {
		return err
	}
	if network.Is4() {
		// for IPv4 networks skip network and broadcast addresses
		p.hostsFirst = next
		p.hostsLast = last.Prev()

	} else {
		// for IPv6, use all addresses
		p.hostsFirst = network
		p.hostsLast = last
	}
	if !p.hostsLast.IsValid() {
		return errors.New("failed to calculate last address")
	}
	return nil
}

func calculateLastHostInRange(prefix netip.Prefix) (netip.Addr, error) {
	prefix = prefix.Masked()
	first := prefix.Addr()

	// single address case
	if prefix.IsSingleIP() {
		return first, nil
	}

	// convert to net.IPNet
	ip := net.IP(first.AsSlice())
	mask := net.CIDRMask(prefix.Bits(), first.BitLen())

	// calculate last address by ORing with inverted mask
	lastIP := make(net.IP, len(ip))
	for i := range ip {
		lastIP[i] = ip[i] | ^mask[i]
	}
	last, ok := netip.AddrFromSlice(lastIP)
	if !ok || !last.IsValid() {
		return netip.Addr{}, errors.New("failed to calculate last address")
	}

	return last, nil
}
