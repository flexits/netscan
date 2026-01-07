package ui

import (
	"github.com/pterm/pterm"
)

func PrintflnLabeledError(format string, a ...any) {
	pterm.Error.Printfln(format, a...)
}

func PrintflnLabeledInfo(format string, a ...any) {
	pterm.Info.Printfln(format, a...)
}

func PrintflnInfo(format string, a ...any) {
	pterm.ThemeDefault.InfoMessageStyle.Printfln(format, a...)
}

func PrintflnSuccess(format string, a ...any) {
	pterm.ThemeDefault.SuccessMessageStyle.Printfln(format, a...)
}

func PrintflnWarn(format string, a ...any) {
	pterm.ThemeDefault.WarningMessageStyle.Printfln(format, a...)
}
