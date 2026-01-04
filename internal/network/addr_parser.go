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
	length     int
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

// Get number of hosts in the parsed range
func (p *AddrParser) GetHostsLength() int {
	return p.length
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
		if !ip.IsPrivate() {
			return errors.New("not a private network")
		}
		p.hostsFirst = ip
		p.hostsLast = ip
		p.cidr = netip.PrefixFrom(ip, ip.BitLen())
		p.length = 1
		return nil
	}
	// it's a CIDR range
	prefix = prefix.Masked()
	p.cidr = prefix
	err = p.populateHosts()
	if err != nil {
		return err
	}
	if !p.hostsFirst.IsPrivate() || !p.hostsLast.IsPrivate() {
		return errors.New("not a private network")
	}
	return nil
}

func (p *AddrParser) populateHosts() error {
	network := p.cidr.Addr()
	if !network.IsValid() {
		return errors.New("invalid start address")
	}
	is4 := network.Is4()
	bits := p.cidr.Bits()
	if bits == 128 || (is4 && bits == 32) {
		// single address
		p.hostsFirst = network
		p.hostsLast = network
		p.length = 1
		return nil
	}
	next := network.Next()
	if !next.IsValid() {
		return errors.New("failed to calculate next address")
	}
	if bits == 127 || (is4 && bits == 31) {
		// two addresses only; no broadcast for IPv4
		p.hostsFirst = network
		p.hostsLast = next
		p.length = 2
		return nil
	}
	// larger networks
	last, err := calculateLastHostInRange(p.cidr)
	if err != nil {
		return err
	}
	length, err := limitRangeLength(p.cidr)
	if err != nil {
		return err
	}
	if is4 {
		// for IPv4 networks skip network and broadcast addresses
		p.hostsFirst = next
		p.hostsLast = last.Prev()
		p.length = length - 2

	} else {
		// for IPv6, use all addresses
		p.hostsFirst = network
		p.hostsLast = last
		p.length = length
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

func limitRangeLength(prefix netip.Prefix) (int, error) {
	totalBits := 128
	if prefix.Addr().Is4() {
		totalBits = 32
	}

	hostBits := totalBits - prefix.Bits()
	if hostBits < 0 {
		return 0, errors.New("invalid CIDR prefix length")
	}

	if hostBits > 16 {
		return 0, errors.New("address range exceeds 65536")
	}

	count := uint64(1) << hostBits
	if count > 65536 {
		return 0, errors.New("address range exceeds 65536")
	}

	return int(count), nil
}
