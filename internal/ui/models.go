package ui

// Options structure holds parsed command line options
type Options struct {
	CIDR           string
	IsVerbose      bool
	UseTCPScan     bool
	UseNbstat      bool
	UsePing        bool
	UseFingerprint bool
	UseBannerGrab  bool
	Threads        byte
}
