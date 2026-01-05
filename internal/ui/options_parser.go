package ui

import (
	"errors"
	"os"

	"github.com/jessevdk/go-flags"
)

const strUsage = "<IP address or CIDR range> [OPTIONS]"

const strDescription = `
netscan is a program that allows to discover devices on the local network.

CIDR range format example:
  192.168.0.0/24 for addresses from 192.168.0.1 to 192.168.0.254`

// Options definition for jessevdk/go-flags package.
type cliOptions struct {
	Verbose bool `short:"v" long:"verbose" description:"Verbose output"`
	Tcp     bool `short:"c" long:"tcp" description:"Enable TCP connect probing"`
	Ping    bool `short:"p" long:"ping" description:"Enable ping (ICMP echo) scanning"`
	Nbstat  bool `short:"n" long:"nbstat" description:"Enable NetBIOS NBSTAT probing (IPv4 only)"`
	Threads byte `short:"t" long:"threads" description:"Override number of concurrent threads to use"`
}

type OptionsParser struct {
	opts   *cliOptions
	parser *flags.Parser
}

// OptionsParser performs command line arguments parsing.
func NewOptionsParser() *OptionsParser {
	options := &cliOptions{}
	parser := flags.NewParser(options, flags.Default)
	parser.LongDescription = strDescription
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
		CIDR:       args[0],
		IsVerbose:  p.opts.Verbose,
		UsePing:    p.opts.Ping,
		UseNbstat:  p.opts.Nbstat,
		UseTCPScan: p.opts.Tcp,
		Threads:    p.opts.Threads,
	}, nil
}
