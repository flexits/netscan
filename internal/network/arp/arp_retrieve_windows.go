package arp

// Parses the "arp -a" output
// and returns a slice of IP - MAC pairs
// or (nil, error) in case of an error.
func RetrieveArpTable() ([]ArpInfo, error) {
	/*
		data, err := exec.Command("arp", "-a").Output()
		if err != nil {
			return nil, nil
		}
	*/
	return nil, nil
}
