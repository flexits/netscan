package main

import (
	"context"
	"errors"
	"fmt"
	"netscan/internal/network"
	"netscan/internal/network/scanners"
	"netscan/internal/ui"
	"os"
	"os/signal"
	"runtime"
	"sync"
	"syscall"
	"time"
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
	// set number of threads if not provided by user
	if options.Threads == 0 {
		options.Threads = byte(runtime.GOMAXPROCS(0))
	}
	// enable TCP by default
	options.UseTCPScan = true

	// parse and validate CIDR/address
	addrParser := network.NewAddrParser()
	addrParser.SetVerbosity(options.IsVerbose)
	err = addrParser.ParseCidrOrAddr(options.CIDR)
	if err != nil {
		fmt.Printf("Error parsing CIDR/address: %v\n", err)
		os.Exit(1)
	}

	/*
		fmt.Println("CIDR string:", options.CIDR)
		fmt.Println("Verbose:", options.IsVerbose)
		fmt.Println("TCP Scan:", options.UseTCPScan)
		fmt.Println("Ping:", options.UsePing)
		fmt.Println("Threads:", options.Threads)
		fmt.Println("First host address:", addrParser.GetHostsFirst())
		fmt.Println("Last host address:", addrParser.GetHostsLast())
	*/

	// configure scanners
	scannerOptions := &scanners.ScannersManagerOptions{
		IncludeTCPScan:  options.UseTCPScan,
		IncludeICMPPing: options.UsePing,
		// more scanner types...
		IsVerbose: options.IsVerbose,
	}
	scannerManager := scanners.NewScannersManager(scannerOptions)

	// prepare scanning
	ctx, cancel := signal.NotifyContext(context.Background(), os.Interrupt, syscall.SIGTERM)
	defer cancel()

	results := []*scanners.Target{}
	var muResults sync.Mutex

	// start scanning
	fmt.Printf("Starting scan of %v using %d threads\n", addrParser.GetCIDR(), options.Threads)

	var wg sync.WaitGroup
	wg.Go(func() {
		// copy results to output slice
		var wgConsumer sync.WaitGroup
		out := make(chan *scanners.Target, options.Threads)
		wgConsumer.Go(func() {
			for r := range out {
				select {
				case <-ctx.Done():
					return
				default:
					muResults.Lock()
					results = append(results, r)
					muResults.Unlock()
				}
			}
		})

		// run a number of workers limited by options.Threads
		var wgWorkers sync.WaitGroup
		sem := make(chan struct{}, options.Threads)
		for addr := range addrParser.Hosts() {
			select {
			case <-ctx.Done():
				return
			default:
				// acquire the semaphore and run worker
				sem <- struct{}{}

				if options.IsVerbose {
					fmt.Printf("Queued %v\n", addr)
				}
				// execute scanning steps and send the result
				wgWorkers.Go(func() {
					defer func() { <-sem }()
					if options.IsVerbose {
						fmt.Printf("Scanning %v\n", addr)
					}
					steps := scannerManager.GetSteps()
					target := &scanners.Target{
						Address: addr,
						Results: make([]*scanners.ScanResult, 0, steps),
					}
					for step := range steps {
						select {
						case <-ctx.Done():
							return
						default:
							scanner, err := scannerManager.GetScanner(step)
							if err != nil {
								break
							}
							scan, err := scanner.Scan(ctx, addr)
							if err != nil {
								continue
							}
							target.Results = append(target.Results, scan)
						}
					}
					out <- target
				})
			}
		}
		wgWorkers.Wait()
		close(out)
		close(sem)
		wgConsumer.Wait()
	})
	wg.Wait()

	// TODO process the results
	/*fmt.Println()
	for _, r := range results {
		fmt.Printf("Scanned %v with results:\n", r.Address)
		for _, s := range r.Results {
			fmt.Printf("%s: %s\n", s.ScannerName, s.Status)
		}
		fmt.Println()
	}*/

	time.Sleep(250 * time.Millisecond)
	os.Exit(0)
}
