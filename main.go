package main

import (
	"context"
	"errors"
	"netscan/internal/network"
	"netscan/internal/network/scanners"
	"netscan/internal/ui"
	"os"
	"os/signal"
	"runtime"
	"sort"
	"strings"
	"sync"
	"syscall"
	"time"

	"github.com/pterm/pterm"
)

const version = "v.0.1"

func main() {
	// parse command line arguments
	optionsParser := ui.NewOptionsParser()
	options, err := optionsParser.ParseArgs()
	if err != nil || options == nil {
		if errors.Is(err, ui.ErrHelpShown) {
			os.Exit(0)
		}
		ui.ShowLabeledError("Error parsing options: %v\n", err)
		os.Exit(1)
	}

	// parse and validate CIDR/address
	addrParser := network.NewAddrParser()
	addrParser.SetVerbosity(options.IsVerbose)
	err = addrParser.ParseCidrOrAddr(options.CIDR)
	if err != nil {
		ui.ShowLabeledError("Error parsing CIDR/address: %v\n", err)
		os.Exit(1)
	}

	// set number of threads if not provided by user
	if options.Threads == 0 {
		options.Threads = byte(runtime.GOMAXPROCS(0))
	}
	// enable TCP by default
	options.UseTCPScan = true

	/*
		fmt.Println("CIDR string:", options.CIDR)
		fmt.Println("Verbose:", options.IsVerbose)
		fmt.Println("TCP Scan:", options.UseTCPScan)
		fmt.Println("Ping:", options.UsePing)
		fmt.Println("Threads:", options.Threads)
		fmt.Println("First host address:", addrParser.GetHostsFirst())
		fmt.Println("Last host address:", addrParser.GetHostsLast())
		fmt.Println("Hosts count:", addrParser.GetHostsLength())
	*/

	// configure scanners
	scannerOptions := &scanners.ScannersManagerOptions{
		IncludeTCPScan:  options.UseTCPScan,
		IncludeICMPPing: options.UsePing,
		// TODO more scanner types...
		IsVerbose: options.IsVerbose,
	}
	scannerManager := scanners.NewScannersManager(scannerOptions)

	ui.ShowLabeledInfo("netscan %s", version)
	ui.ShowLabeledInfo("Target: %v", addrParser.GetCIDR())
	ui.ShowLabeledInfo("Scan methods: %s",
		strings.Join(scannerManager.GetNames(), ", "))
	ui.ShowLabeledInfo("Using %d threads", options.Threads)
	spinnerInfo, _ := pterm.DefaultSpinner.Start("Scanning...")

	// prepare scanning
	ctx, cancel := signal.NotifyContext(context.Background(), os.Interrupt, syscall.SIGTERM)
	defer cancel()

	results := []*scanners.TargetInfo{}
	var muResults sync.Mutex

	// start scanning
	var wg sync.WaitGroup
	wg.Go(func() {
		// copy results to output slice
		var wgConsumer sync.WaitGroup
		out := make(chan *scanners.TargetInfo, options.Threads)
		wgConsumer.Go(func() {
			for r := range out {
				select {
				case <-ctx.Done():
					return
				default:
					if r.GetState() != scanners.HostDead {
						muResults.Lock()
						results = append(results, r)
						muResults.Unlock()
					}
				}
			}
			muResults.Lock()
			sort.Slice(results, func(i, j int) bool {
				return results[i].Address.Compare(results[j].Address) < 0
			})
			muResults.Unlock()
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
					ui.ShowInfoString("Queued %v\n", addr)
				}
				// execute scanning steps and send the result
				wgWorkers.Go(func() {
					defer func() { <-sem }()
					if options.IsVerbose {
						ui.ShowInfoString("Scanning %v\n", addr)
					}
					steps := scannerManager.GetSteps()
					target := &scanners.TargetInfo{
						Address: addr,
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
							// TODO get rid of the hardcoded timeout
							err = scanner.ScanTimeout(ctx, target, 1*time.Second)
							if err != nil {
								continue
							}
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

	select {
	case <-ctx.Done():
		spinnerInfo.UpdateText("Interrupted!")
		spinnerInfo.Warning()
	default:
		spinnerInfo.UpdateText("Finished!")
		spinnerInfo.Success()
	}

	// TODO process the results
	/*fmt.Println()
	for _, r := range results {
		fmt.Printf("Scanned %v with results:\n", r.Address)
		for _, s := range r.Results {
			fmt.Printf("%s: %s\n", s.ScannerName, s.Status)
		}
		fmt.Println()
	}*/

	// grant time for goroutines to finish
	time.Sleep(500 * time.Millisecond)
	os.Exit(0)
}
