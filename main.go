package main

import (
	"errors"
	"fmt"
	_ "net/netip"
	"netscan/internal/ui"
	"os"
)

func main() {
	options, err := ui.ParseArgs()
	if err != nil {
		if errors.Is(err, ui.ErrHelpShown) {
			os.Exit(0)
		}
		fmt.Printf("Error parsing options: %v\n", err)
		os.Exit(1)
	}
	fmt.Println("CIDR:", options.CIDR)
	fmt.Println("Verbose:", options.IsVerbose)
	os.Exit(0)
}
