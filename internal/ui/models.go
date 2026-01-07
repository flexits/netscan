package ui

// Options structure holds parsed command line options
type Options struct {
	CIDR           string
	IsVerbose      bool
	UseTCPScan     bool
	UseNbstat      bool
	UsePing        bool
	UseArpCache    bool
	UseFingerprint bool
	UseBannerGrab  bool
	Threads        byte
}

// Returns true is any of the available scanners is selected for usage.
func (o *Options) IsAnyScanSelected() bool {
	return o.UseTCPScan || o.UsePing || o.UseNbstat || o.UseArpCache
}
