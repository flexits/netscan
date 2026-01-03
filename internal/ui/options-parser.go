package ui

import (
	"errors"
	"os"

	"github.com/jessevdk/go-flags"
)

const strUsage = "<IP address or CIDR range> [OPTIONS]"

const strDesription = `
netscan is a program that allows to discover devices on the local network.

CIDR range format example:
  192.168.0.0/24 for addresses from 192.168.0.1 to 192.168.0.254`

// Options definition for jessevdk/go-flags package.
type cliOptions struct {
	Verbose bool `short:"v" long:"verbose" description:"Verbose output"`
}

type OptionsParser struct {
	opts   *cliOptions
	parser *flags.Parser
}

// OptionsParser performs command line arguments parsing.
func NewOptionsParser() *OptionsParser {
	options := &cliOptions{}
	parser := flags.NewParser(options, flags.Default)
	parser.LongDescription = strDesription
	parser.Usage = strUsage
	return &OptionsParser{
		opts:   options,
		parser: parser,
	}
}

// Writes CLI help message to the standard output.
func (p *OptionsParser) ShowHelpMessage() {
	p.parser.WriteHelp(os.Stdout)
}

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
func (p *OptionsParser) ParseArgs() (*Options, error) {
	args, err := p.parser.Parse()
	if err != nil {
		var flagsErr *flags.Error
		if errors.As(err, &flagsErr) && flagsErr.Type == flags.ErrHelp {
			return nil, ErrHelpShown
		}
		return nil, err
	}
	if len(args) < 1 {
		p.ShowHelpMessage()
		return nil, ErrHelpShown
	}
	return &Options{
		CIDR:      args[0],
		IsVerbose: p.opts.Verbose,
	}, nil
}
