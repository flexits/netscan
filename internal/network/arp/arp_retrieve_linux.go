package arp

// Parses the ARP table at /proc/net/arp
// and returns a slice of IP - MAC pairs
// or (nil, error) in case of an error.
func RetrieveArpTable() ([]ArpInfo, error) {
	/*
		f, err := os.Open("/proc/net/arp")
		if err != nil {
			return nil, nil
		}
		defer f.Close()
	*/
	return nil, nil
}
