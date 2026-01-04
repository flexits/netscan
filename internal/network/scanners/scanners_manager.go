package scanners

import "errors"

type ScannersManagerOptions struct {
	IncludeTCPScan  bool
	IncludeICMPPing bool
	// more scanner types...
	IsVerbose bool // TODO not implemented yet
}

type ScannersManager struct {
	steps    int
	scanners []Scanner
}

func NewScannersManager(options *ScannersManagerOptions) *ScannersManager {
	s := &ScannersManager{}
	if options.IncludeTCPScan {
		s.scanners = append(s.scanners, NewTCPScanner())
	}
	if options.IncludeICMPPing {
		s.scanners = append(s.scanners, NewPingScanner())
	}
	s.steps = len(s.scanners)
	return s
}

func (m *ScannersManager) GetSteps() int {
	return m.steps
}

func (m *ScannersManager) GetScanner(step int) (Scanner, error) {
	if step < 0 || step >= len(m.scanners) {
		return nil, errors.New("scanner step number out of range")
	}
	return m.scanners[step], nil
}
