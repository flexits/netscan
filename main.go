package main

import (
	"context"
	"errors"
	"fmt"
	"netscan/internal/network"
	"netscan/internal/network/arp"
	"netscan/internal/network/scanners"
	"netscan/internal/ui"
	"os"
	"os/signal"
	"sort"
	"strings"
	"sync"
	"syscall"
	"time"

	"github.com/pterm/pterm"
)

const version = "v.0.1"

func main() {
	/*
		// Debug
		fh, err := os.Create("heap.pprof")
		if err != nil {
			fmt.Printf("Failed to create heap.pprof %v", err)
			os.Exit(1)
		}
		defer fh.Close()
		fc, err := os.Create("cpu.pprof")
		if err != nil {
			fmt.Printf("Failed to create cpu.pprof %v", err)
			os.Exit(1)
		}
		defer fc.Close()
		if err := pprof.StartCPUProfile(fc); err != nil {
			fmt.Printf("Failed to start profiling %v", err)
			os.Exit(1)
		}
	*/
	// parse command line arguments
	optionsParser := ui.NewOptionsParser()
	options, err := optionsParser.ParseArgs()
	if err != nil || options == nil {
		if errors.Is(err, ui.ErrHelpShown) {
			return
		}
		ui.PrintflnLabeledError("Error parsing options: %v\n", err)
		os.Exit(1)
	}

	// parse and validate CIDR/address
	addrParser := network.NewAddrParser()
	addrParser.SetVerbosity(options.IsVerbose)
	err = addrParser.ParseCidrOrAddr(options.CIDR)
	if err != nil {
		ui.PrintflnLabeledError("Error parsing CIDR/address: %v\n", err)
		os.Exit(1)
	}

	// set number of threads if not provided by user
	if options.Threads == 0 {
		//options.Threads = byte(runtime.GOMAXPROCS(0))
		// we are i/o-bound, not cpu-bound, so may increase the number
		options.Threads = 128
	}
	// enable TCP by default
	if !options.IsAnyScanSelected() {
		options.UseTCPScan = true
		options.UseArpCache = true
	}

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
		IncludeNbstat:   options.UseNbstat,
		// TODO more scanner types...
		IsVerbose: options.IsVerbose,
	}
	scannerManager := scanners.NewScannersManager(scannerOptions)

	ui.PrintflnInfo("netscan %s", version)
	ui.PrintflnLabeledInfo("Target: %v", addrParser.GetCIDR())
	scanNames := scannerManager.GetNames()
	if options.UseArpCache {
		scanNames = append(scanNames, "ARP Table")
	}
	ui.PrintflnLabeledInfo("Scan methods: %s", strings.Join(scanNames, ", "))
	ui.PrintflnLabeledInfo("Using %d threads", options.Threads)
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
					ui.PrintflnInfo("Queued %v\n", addr)
				}
				// execute scanning steps and send the result
				wgWorkers.Go(func() {
					defer func() { <-sem }()
					if options.IsVerbose {
						ui.PrintflnInfo("Scanning %v\n", addr)
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
								continue
							}
							// TODO get rid of the hardcoded timeout
							scanner.ScanTimeout(ctx, target, 1*time.Second)
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

		// enrich results with ARP cache contents
		if options.UseArpCache {
			arp, err := arp.GetArpTable()
			if err == nil {
				muResults.Lock()
				for _, r := range results {
					m, ok := arp[r.Address]
					if !ok {
						continue
					}
					r.Mac = m.Mac
					m.IsProcessed = true
				}
				muResults.Unlock()
				targetCIDR := addrParser.GetCIDR()
				for ip, m := range arp {
					if m.IsProcessed {
						continue
					}
					if !targetCIDR.Contains(ip) {
						continue
					}
					res := scanners.TargetInfo{
						Address: ip,
						Mac:     m.Mac,
					}
					res.SetState(scanners.HostUnknown)
					muResults.Lock()
					results = append(results, &res)
					muResults.Unlock()
				}
			}
		}

		// sort the results
		muResults.Lock()
		sort.Slice(results, func(i, j int) bool {
			return results[i].Address.Compare(results[j].Address) < 0
		})
		muResults.Unlock()
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

	// process the results
	// TODO refact this spaghetti
	fmt.Println()
	for _, r := range results {
		state := r.GetState()
		if state != scanners.HostAlive && state != scanners.HostUnknown {
			fmt.Printf("Scanned %v with state %s\n", r.Address, state)
		} else {
			if state == scanners.HostAlive {
				ui.PrintflnSuccess("%v is %s", r.Address, state)
			}
			if state == scanners.HostUnknown {
				ui.PrintflnWarn("%v is %s", r.Address, state)
			}
			if len(r.Mac) > 0 {
				fmt.Printf("\t%s\n", r.Mac)
			}
			if len(r.HostName) > 0 {
				fmt.Printf("\t%s\n", r.HostName)
			}
			if len(r.Workgroup) > 0 {
				fmt.Printf("\t%s\n", r.Workgroup)
			}
		}
		for _, c := range r.Comments {
			fmt.Printf("\t\t%s\n", c)
		}
		fmt.Println()
	}
	/*
		// Debug
		pprof.StopCPUProfile()
		if err = pprof.WriteHeapProfile(fh); err != nil {
			fmt.Printf("Failed to write heap profile %v", err)
		}
	*/
	// grant time for goroutines to finish
	time.Sleep(500 * time.Millisecond)
}
