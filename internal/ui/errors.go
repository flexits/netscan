package ui

import "errors"

// Generic/unknown error on parsing command line arguments.
var ErrArgParsing = errors.New("error parsing arguments")

// Error on parsing address (CIDR).
var ErrAddrParsing = errors.New("error parsing address")

// Indicates that the help message has been shown,
// the program should exit without error.
var ErrHelpShown = errors.New("help shown")
