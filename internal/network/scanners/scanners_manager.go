package scanners

import "errors"

// Configure what scanners to include and other options
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

// Returns a configured set of ready to use scanners
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

// Number of scanning steps - that is, the number of scanners
func (m *ScannersManager) GetSteps() int {
	return m.steps
}

// Get a scanner by its number
func (m *ScannersManager) GetScanner(step int) (Scanner, error) {
	if step < 0 || step >= len(m.scanners) {
		return nil, errors.New("scanner step number out of range")
	}
	return m.scanners[step], nil
}

// Names of all scanners in the set
func (m *ScannersManager) GetNames() []string {
	result := make([]string, 0, len(m.scanners))
	for _, s := range m.scanners {
		result = append(result, s.GetName())
	}
	return result
}
