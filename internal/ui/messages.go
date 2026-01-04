package ui

import (
	"netscan/internal/network"
	"netscan/internal/network/scanners"
	"strings"

	"github.com/pterm/pterm"
)

func ShowInstanceInfo(options *Options,
	addrParser *network.AddrParser,
	scannerManager *scanners.ScannersManager) {

	pterm.Info.Printfln("Target: %v", addrParser.GetCIDR())
	pterm.Info.Printfln("Scan methods: %s",
		strings.Join(scannerManager.GetNames(), ", "))
	pterm.Info.Printfln("Using %d threads", options.Threads)
}

func ShowLabeledError(format string, a ...any) {
	pterm.Error.Printfln(format, a...)
}

func ShowInfoString(format string, a ...any) {
	pterm.ThemeDefault.InfoMessageStyle.Printfln(format, a...)
}
