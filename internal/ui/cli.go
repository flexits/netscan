package ui

import (
	"errors"
	"fmt"
	"os"

	"netscan/internal/network"

	"github.com/jessevdk/go-flags"
)

const strUsage = "<IP address or CIDR range> [OPTIONS]"

const strDesription = `
netscan is a program that allows to discover devices on the local network.

CIDR range format example:
  192.168.0.0/24 for addresses from 192.168.0.1 to 192.168.0.254`

// Options definition for jessevdk/go-flags package.
type CliOptions struct {
	Verbose bool `short:"v" long:"verbose" description:"Verbose output"`
}

var cliOptions = &CliOptions{}

// Parses command line arguments.
//
// Returns:
//   - Options structure pointer with parsed values or nil on error;
//   - error value or nil on success.
//
// Possible errors:
//   - ErrHelpShown: help message has been shown, program should exit without error;
//   - ErrArgParsing: generic error parsing command line arguments;
//   - other errors returned by the jessevdk/go-flags package.
func ParseArgs() (*Options, error) {
	var parser = flags.NewParser(cliOptions, flags.Default)
	parser.LongDescription = strDesription
	parser.Usage = strUsage
	args, err := parser.Parse()
	if err != nil {
		var flagsErr *flags.Error
		if errors.As(err, &flagsErr) && flagsErr.Type == flags.ErrHelp {
			return nil, ErrHelpShown
		}
		return nil, err
	}
	if len(args) < 1 {
		parser.WriteHelp(os.Stdout)
		return nil, ErrHelpShown
	}
	prefix, err := network.ParseCidrOrAddr(args[0])
	if err != nil || prefix == nil {
		return nil, ErrAddrParsing
	}
	fmt.Println(prefix)
	options := Options{
		CIDR:      args[0],
		IsVerbose: cliOptions.Verbose,
	}
	return &options, nil
}
