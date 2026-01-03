package main

import (
	"errors"
	"fmt"
	"netscan/internal/network"
	"netscan/internal/ui"
	"os"
)

func main() {
	// parse command line arguments
	optionsParser := ui.NewOptionsParser()
	options, err := optionsParser.ParseArgs()
	if err != nil || options == nil {
		if errors.Is(err, ui.ErrHelpShown) {
			os.Exit(0)
		}
		fmt.Printf("Error parsing options: %v\n", err)
		os.Exit(1)
	}

	// parse and validate CIDR/address
	addrParser := network.NewAddrParser()
	addrParser.SetVerbosity(options.IsVerbose)
	err = addrParser.ParseCidrOrAddr(options.CIDR)
	if err != nil {
		fmt.Printf("Error parsing CIDR/address: %v\n", err)
		os.Exit(1)
	}

	fmt.Println("CIDR string:", options.CIDR)
	fmt.Println("Verbose:", options.IsVerbose)
	fmt.Println("First host address:", addrParser.GetHostsFirst())
	fmt.Println("Last host address:", addrParser.GetHostsLast())
	/*for addr := range addrParser.Hosts() {
		fmt.Println(addr)
	}*/
	os.Exit(0)
}
