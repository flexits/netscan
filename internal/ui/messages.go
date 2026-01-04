package ui

import (
	"github.com/pterm/pterm"
)

func ShowLabeledError(format string, a ...any) {
	pterm.Error.Printfln(format, a...)
}

func ShowLabeledInfo(format string, a ...any) {
	pterm.Info.Printfln(format, a...)
}

func ShowInfoString(format string, a ...any) {
	pterm.ThemeDefault.InfoMessageStyle.Printfln(format, a...)
}
