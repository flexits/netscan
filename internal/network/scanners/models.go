package scanners

import (
	"net/netip"
	"strconv"
)

// Represents a network device state.
type HostState int

const (
	HostDead HostState = iota
	HostUnknown
	HostAlive
)

func (s HostState) String() string {
	switch s {
	case HostDead:
		return "Offline"
	case HostUnknown:
		return "Unknown"
	case HostAlive:
		return "Online"
	default:
		return strconv.Itoa(int(s))
	}
}

// Host scan results.
type TargetInfo struct {
	Address   netip.Addr
	state     HostState
	Mac       string
	HostName  string
	Workgroup string
	// whatever else...
	Comments []string
}

// Return the most optimistic estimation of the host state.
func (t *TargetInfo) GetState() HostState {
	return t.state
}

// Set the host state.
// Allows only switch to more optimistic state:
// HostDead -> HostUnknown is okay, but HostAlive -> HostDead is ignored.
func (t *TargetInfo) SetState(s HostState) {
	switch {
	case t.state == HostDead:
		t.state = s
	case t.state == HostUnknown && s == HostAlive:
		t.state = HostAlive
	default:
		return
	}
}
