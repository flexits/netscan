# netscan

<img width="600" alt="netscan-main-1" src="https://github.com/user-attachments/assets/ed181049-bd7b-4be3-adc6-5577527f3561" />

A console utility to discover local network hosts (devices).

**Designed for speed**: utilizes a customizable network scanning/probing pipeline in parallel mode. By default, uses up to 128 concurrent threads, completing a standard /24 SOHO subnet in a matter of seconds.

**No elevated privileges** required, runs completely in user-space. However, this imposes certain restrictions, not all scanning/probing methods can be implemented.

**Cross-platform**: Windows, Linux, macOS; and **portable**: the built binary contains all required dependencies within itself and may safely be copied wherever it's needed.

And, of course, **colored** console output with spinner 😊

*Disclaimer:* The application is in the **alpha stage**, not all planned features are implemented yet, and there may be bugs as well.

## Usage

`netscan <IP address or CIDR range> [OPTIONS]`

The scan target is passed as an IP or CIDR string. In the latter case, network and broadcast IPv4 addresses are automatically omitted from the scan range.  
Only private networks are allowed.  
There's a limit of 65,536 addresses per single scan. *This is not due to any code limitations, just an arbitrary decision like "ought to be enough for anybody"* 😉

Options are used to configure the scanning pipeline. Each target address is challenged with different detection/probing methods sequentially. Currently available options are:  
`-c`, `--tcp`     TCP connection probe *(not tested with IPv6 yet)*  
`-n`, `--nbstat`  NetBIOS NBSTAT probe, only IPv4, useful against Windows machines  
`-p`, `--ping`    ICMP Echo (ping) probe *(currently only Windows and only IPv4)*  
`-a`, `--arp`     ARP passive discovery (local system cache lookup) *(currently only macOS, \*BSD)*
By default, if no options are provided, the TCP probing with ARP passive discovery is used. 

The maximum number of parallel threads may be customized with `-t`, `--threads` switch. The default value is 128. One target is one thread, and one scanner takes approximately a second – that is, a ubiquitous IPv4 /24 home subnet (254 hosts) scan with all the 3 currently available scanners enabled (`-cnp` option) will last about 🚀 6 seconds. Nevertheless, you're safe to interrupt the program with `Ctrl+C` any time you wish.

## How to build

It takes 5 easy steps. Ensure you have [Go](https://go.dev/doc/install) installed in your system (only for build, not required later to run, the Go binaries are self-contained) beforehand.

```
# 1. Clone the repository
git clone https://github.com/flexits/netscan

# 2. Navigate to project directory
cd netscan

# 3. Download dependencies
go mod tidy

# 4. Build the project
go build .

# 5. Run the application
./netscan
```

## Pending features

- Local ARP table lookup to gather MAC addresses.
- Extend ICMP Echo functionality to IPv6 and Linux/macOS.
- More up to date or sophisticated probing techniques: maybe mDNS/LLMNR, SCTP Init, IPv6 Neighbor Solicitation, something else.
- Extended functionality like OS fingerprinting or banner grabbing.

## Inner workings

For those who are interested, you're not required to read this just to use the app.

First of all, **external libraries**: [pterm](https://github.com/pterm/pterm) to beautify console output and [go-flags](https://github.com/jessevdk/go-flags) to parse command line arguments.

### Execution pipeline

The target address range is processed, validated, and its boundaries (first and last addresses) are determined. To save memory (RAM is a bit 💰 pricey these days, isn’t it?), we do not pre-generate an array of target addresses for the range; instead, the next address is calculated dynamically on demand.

Each detection method is implemented as a discrete thread-safe piece of code. All scanners have a uniform **Scanner** interface and there's a **ScannersManager** service that takes the parsed user input and creates only the needed scanners. Every scanner has 1 second timeout (maybe will fine-tune later if needed).

For each target address we start a dedicated goroutine (with respect to the limit, of course - after we've hit the ceiling, we're waiting for some goroutines to complete). Inside the goroutine, we get the configured scanners from the ScannersManager and call the scanning code in sequence.

The scan results are filtered (the unreachable and unknown hosts are removed) and printed on the screen.

### Scanners

TCP scanner attempts to open connection to the target host on a number of ports (80, 443, 22, 445, 3389). Uses the standard Go runtime, nothing fancy.  

NetBIOS scanner works the same way, sends the NBSTAT question to the target's 137/UDP and waits for the answer. It's rather [ancient](https://datatracker.ietf.org/doc/html/rfc1002), only IPv4 by design and is useful mainly against [Windows](https://learn.microsoft.com/en-us/openspecs/windows_protocols/ms-brws/d2d83b29-4b62-479e-b427-9b750303387b) machines (maybe also some printers and stuff like that). 

ICMP Echo scanner (Windows) utilizes `IcmpSendEcho` WinAPI function to send requests and get responses. For Linux/macOS I'll probably stick with Google's x/net/icmp package.

ARP parser (macOS, \*BSD) utilizes the corresponding native syscall and is based on the code of [goarp](https://github.com/juruen/goarp/blob/master/arp/arp_bsd.go) project which in it's turn is an adaptation of the \*BSD `arp` utility source code.
