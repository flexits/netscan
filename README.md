# netscan

A console utility to discover local network hosts (devices).

**It's a draft, not usable yet!**

## Capabilities

Scan target is passed as an IP/CIDR string. In the latter case, network and broadcast IPv4 addresses are automatically omitted from the scan range.

Scan types are configured via command line switches.

## Under the hood

### Architecture consideration

A scanner is a distinct fragment of code performing only one task - TCP scan, ICMP echo etc.
A scanner is initialized with a target host address and returns a structure - scan result.

Application startup flag defines a number of workers to use and what scanners are needed.
Workers scan different targets simultaneously. Required scanners form a pipeline inside of
a worker (each target goes through the entire set of scanners - pipeline).

Iterator over a range of host addresses pushes addresses into a channel in form of
a structure containing address and a slice for scan results.

We use a worker pool; each worker consumes one address from a channel and starts processing it.

Each worker must implement a pipeline inside. The pipeline is constructed from
the scanners we are using.

Each scanner returns a scan result that is appended to the scan results slice.

### Implementation consideration

A goroutine: reads addresses, writes to an input channel (unbuffered),
then closes the channel (range iterator).

A goroutine: reads from the channel (range over channel), acquires a semaphore,
starts a worker goroutine, releases the semaphore when done. Uses a WaitGroup
to wait for all workers to finish, then closes the output channel.

A worker goroutine: constructs a pipeline of scanners based on Options flags,
runs each scanner in sequence, appends results to the output channel (unbuffered).

A goroutine: reads from the output channel (range over channel),
stores results somewhere (a slice or similar).

In the end we have a slice of scan results, both channels are closed, all goroutines are done.

Inside of a worker: no goroutines, just sequential execution of scanners.
Consider a pool of scanners to reuse (not sure if it's really justified).

Each scanner must implement a context cancellation mechanism to avoid hanging.

Graceful shutdown for all of the above is absolutely required!

### Caveats

1. Root/admin rights needed almost for everything except net.Dial. Check with `os.Geteuid() == 0` (and on Windows?)
2. Platform dependency?
3. Winpcap/Npcap required on Windows

### Network discovery methods

- ICMP echo (ping)
- TCP SYN 443
- TCP ACK 80
- ICMP Timestamp Request (IPv4 only)
- ARP scan (IPv4 only)
- ARP table (_not a scan actually, contains only visited hosts_)
- IPv6 Neighbor Solicitation (IPv6 only)
- UDP ping 40125
- UDP probe 53
- SCTP init 80

- mDNS discovery
- SNMP query
- NetBIOS

Consider banner grabbing, OS fingerprinting etc.

Reference: Nmap host discovery techniques:
https://nmap.org/book/man-host-discovery.html

### Useful packages

For packet construction:
golang.org/x/net/ipv4
golang.org/x/net/ipv6

https://pkg.go.dev/github.com/j-keck/arping

See also: https://github.com/luijait/GONET-Scanner
