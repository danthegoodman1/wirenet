//wirenet:deterministic

// Package api holds the wire types the control plane, agents, relays and
// clients exchange, and the rules for merging desired-state updates.
package api

import (
	"fmt"
	"maps"
	"net/netip"
	"slices"
	"strings"
	"time"

	"github.com/danthegoodman1/wirenet/internal/model"
)

// Kind is what an interface fronts.
type Kind string

const (
	// Workload is an interface in a workload namespace an agent built.
	Workload Kind = "workload"
	// Gateway is an agent-managed interface that development machines peer
	// with.
	Gateway Kind = "gateway"
	// Device is a development machine running a stock WireGuard client
	// behind a gateway.
	Device Kind = "device"
)

// LeaseState is where an interface's lease stands.
type LeaseState string

const (
	Live LeaseState = "live"
	// Released is a planned removal: peers drain it over the grace period.
	Released LeaseState = "released"
	// Revoked is an immediate removal with no grace period. An expired
	// lease is revoked.
	Revoked LeaseState = "revoked"
)

// Mode decides how a service's clients handle a removed backend.
type Mode string

const (
	// Flip keeps established connections on a removed backend until the
	// grace period ends.
	Flip Mode = "flip"
	// Cutover evicts them at once.
	Cutover Mode = "cutover"
)

// NetworkState is everything one host needs for one network: its interfaces
// there and the services they reach. A network's state on a host depends only
// on the network's records, so its revision says when it last changed.
type NetworkState struct {
	Network  model.NetworkID `json:"network"`
	Name     string          `json:"name"`
	Revision uint64          `json:"revision"`
	// Changed is when the revision committed, which agents measure
	// convergence from.
	Changed time.Time    `json:"changed,omitzero"`
	Prefix6 netip.Prefix `json:"prefix6"`
	Prefix4 netip.Prefix `json:"prefix4,omitzero"`
	MTU     int          `json:"mtu"`
	// Relays is the network's relay set in preference order.
	Relays     []RelayRef  `json:"relays,omitempty"`
	Interfaces []Interface `json:"interfaces"`
	Services   []Service   `json:"services,omitempty"`
	// Unreached holds the addresses of the network's other services, which
	// no interface on this host reaches, sorted. Every namespace rejects
	// them, so a workload dialing an address it learned before a deny
	// leaves no conntrack entry to outlast it.
	Unreached []netip.Addr `json:"unreached,omitempty"`
}

// Domain is the DNS suffix the network's names resolve under.
func (n *NetworkState) Domain() string { return n.Name + ".internal" }

// Interface finds one of this host's interfaces in the network.
func (n *NetworkState) Interface(id model.InterfaceID) (*Interface, bool) {
	i, ok := slices.BinarySearchFunc(n.Interfaces, id, func(x Interface, id model.InterfaceID) int {
		return strings.Compare(string(x.ID), string(id))
	})
	if !ok {
		return nil, false
	}
	return &n.Interfaces[i], true
}

// Service finds a service the host's interfaces reach.
func (n *NetworkState) Service(id model.ServiceID) (*Service, bool) {
	i, ok := slices.BinarySearchFunc(n.Services, id, func(x Service, id model.ServiceID) int {
		return strings.Compare(string(x.ID), string(id))
	})
	if !ok {
		return nil, false
	}
	return &n.Services[i], true
}

// RelayRef names one relay of a network's set and the address agents probe.
type RelayRef struct {
	Relay model.RelayID  `json:"relay"`
	Probe netip.AddrPort `json:"probe"`
}

// Interface is one interface on the host, as the agent should build it.
type Interface struct {
	ID         model.InterfaceID `json:"id"`
	Service    model.ServiceID   `json:"service"`
	Kind       Kind              `json:"kind"`
	PublicKey  model.Key         `json:"public_key"`
	Addr6      netip.Addr        `json:"addr6"`
	Addr4      netip.Addr        `json:"addr4,omitzero"`
	ListenPort uint16            `json:"listen_port"`
	State      LeaseState        `json:"state"`
	Expires    time.Time         `json:"expires"`
	// Name is the interface's own DNS name under the network's domain,
	// member.service, when it holds a member name.
	Name string `json:"name,omitempty"`
	// Peers, sorted by interface: every interface policy connects this one
	// with, live or draining.
	Peers []Peer `json:"peers,omitempty"`
	// Reach lists the services this interface may dial by service address.
	Reach []Reach `json:"reach,omitempty"`
	// Inbound lists the flows this interface accepts.
	Inbound []Inbound `json:"inbound,omitempty"`
	// Egress lists the flows this interface may open to the internet.
	Egress []Egress `json:"egress,omitempty"`
}

// Egress permits flows to the internet.
type Egress struct {
	Proto model.Proto     `json:"proto"`
	Ports model.PortRange `json:"ports"`
}

// Addrs returns the interface's addresses, IPv6 first.
func (i *Interface) Addrs() []netip.Addr {
	if i.Addr4.IsValid() {
		return []netip.Addr{i.Addr6, i.Addr4}
	}
	return []netip.Addr{i.Addr6}
}

// Peer is one entry in an interface's peer table.
type Peer struct {
	Interface model.InterfaceID `json:"interface"`
	Service   model.ServiceID   `json:"service"`
	PublicKey model.Key         `json:"public_key"`
	// Allowed holds the peer's own address in each family both interfaces
	// have, as host prefixes: the identity WireGuard enforces.
	Allowed []netip.Prefix `json:"allowed"`
	// Draining marks a released peer: installed, taking no new flows by
	// service address, removed once the grace period ends.
	Draining bool `json:"draining,omitempty"`
	// Loopback is the peer's listen port when it runs on this host.
	Loopback uint16 `json:"loopback,omitempty"`
	// Keepalive arms persistent-keepalive on this side. On the loopback
	// path exactly one side of a pair carries it.
	Keepalive bool `json:"keepalive,omitempty"`
	// Relays holds this direction's port on each relay of the network's
	// set, in the set's order. Empty on the loopback path.
	Relays []RelayPath `json:"relays,omitempty"`
	// Registration is this direction's secret, from which the agent derives
	// each relay's registration key.
	Registration model.Secret `json:"registration,omitzero"`
	// DialsIn marks a development machine at its gateway: it dials the
	// gateway, so roaming alone sets its endpoint.
	DialsIn bool `json:"dials_in,omitempty"`
	// Fronts lists the development machines this peer, a gateway, carries
	// traffic for: their addresses join the peer's allowed IPs, and each
	// counts as a source of its own service.
	Fronts []Fronted `json:"fronts,omitempty"`
}

// Fronted is a development machine behind a gateway peer.
type Fronted struct {
	Interface model.InterfaceID `json:"interface"`
	Service   model.ServiceID   `json:"service"`
	Allowed   []netip.Prefix    `json:"allowed"`
}

// RelayPath is where an interface sends to reach a peer through one relay.
type RelayPath struct {
	Relay model.RelayID  `json:"relay"`
	Send  netip.AddrPort `json:"send"`
}

// Reach permits dialing a service's address.
type Reach struct {
	Service model.ServiceID `json:"service"`
	Proto   model.Proto     `json:"proto"`
	Ports   model.PortRange `json:"ports"`
}

// Inbound permits flows from a service's interfaces.
type Inbound struct {
	From  model.ServiceID `json:"from"`
	Proto model.Proto     `json:"proto"`
	Ports model.PortRange `json:"ports"`
}

// Service is a service an interface on the host may reach.
type Service struct {
	ID    model.ServiceID `json:"id"`
	Name  string          `json:"name"`
	Addr6 netip.Addr      `json:"addr6"`
	Addr4 netip.Addr      `json:"addr4,omitzero"`
	Mode  Mode            `json:"mode"`
	// Backends lists live backends sorted by interface. Draining backends
	// own no slots.
	Backends []Backend `json:"backends,omitempty"`
}

// Backend is one interface standing behind a service.
type Backend struct {
	Interface model.InterfaceID `json:"interface"`
	Addr6     netip.Addr        `json:"addr6"`
	Addr4     netip.Addr        `json:"addr4,omitzero"`
	// Name is the backend's own DNS name under the network's domain,
	// member.service, when it holds a member name.
	Name string `json:"name,omitempty"`
}

// NetworkRef is a network a host holds state for, at a revision.
type NetworkRef struct {
	Network  model.NetworkID `json:"network"`
	Revision uint64          `json:"revision"`
}

// StateUpdate answers an agent's poll. It carries every network whose
// revision passed the generation the agent asked from, and names every
// network the host holds state for, so the agent drops the rest.
type StateUpdate struct {
	Host       model.HostID   `json:"host"`
	Generation uint64         `json:"generation"`
	Networks   []NetworkState `json:"networks,omitempty"`
	Present    []NetworkRef   `json:"present"`
}

// HostState is an agent's merged view of what the control plane wants.
type HostState struct {
	Generation uint64
	Networks   map[model.NetworkID]*NetworkState
}

// NewHostState returns an empty state at generation zero.
func NewHostState() *HostState {
	return &HostState{Networks: map[model.NetworkID]*NetworkState{}}
}

// Apply merges an update. A network the update carries replaces the one
// held unless the held one is newer, which happens when an attach delivered
// it first; a network the update leaves out of Present is dropped, unless
// the held one is newer than the whole update, which then predates it. An
// update older than the generation held changes nothing, and so does one
// that fails a check.
func (h *HostState) Apply(u StateUpdate) error {
	if u.Generation < h.Generation {
		// An answer that arrived out of order: everything it says, a newer
		// update already said.
		return nil
	}
	present := map[model.NetworkID]uint64{}
	for _, ref := range u.Present {
		present[ref.Network] = ref.Revision
	}
	// The merge builds a new map, which replaces the held one only once
	// every check passes.
	next := make(map[model.NetworkID]*NetworkState, len(h.Networks))
	maps.Copy(next, h.Networks)
	for i := range u.Networks {
		n := u.Networks[i]
		rev, ok := present[n.Network]
		if !ok || rev != n.Revision {
			return fmt.Errorf("update carries %s at %d but lists it at %d", n.Network, n.Revision, rev)
		}
		if held, ok := next[n.Network]; ok && held.Revision > n.Revision {
			continue
		}
		next[n.Network] = &n
	}
	for _, id := range slices.Sorted(maps.Keys(next)) {
		rev, ok := present[id]
		if !ok {
			if next[id].Revision <= u.Generation {
				delete(next, id)
			}
			continue
		}
		if next[id].Revision < rev {
			return fmt.Errorf("update lists %s at %d but carries nothing newer than %d", id, rev, next[id].Revision)
		}
	}
	for _, ref := range u.Present {
		if _, ok := next[ref.Network]; !ok {
			return fmt.Errorf("update lists %s at %d but this host holds nothing for it", ref.Network, ref.Revision)
		}
	}
	h.Networks = next
	if u.Generation > h.Generation {
		h.Generation = u.Generation
	}
	return nil
}

// Merge takes one network's state outside a poll, as an attach delivers it.
// A network held at a newer revision stays. So does the absence of one at
// or below the generation held: the poll that delivered that generation
// listed every network the host then had, so it had dropped this one, as
// a rescope or the network's deletion does, and an attach answer that
// arrived late must not bring it back.
func (h *HostState) Merge(n NetworkState) {
	held, ok := h.Networks[n.Network]
	if ok && held.Revision > n.Revision || !ok && n.Revision <= h.Generation {
		return
	}
	h.Networks[n.Network] = &n
}

// NetworkIDs returns the held networks in order.
func (h *HostState) NetworkIDs() []model.NetworkID {
	return slices.Sorted(maps.Keys(h.Networks))
}

// Interface finds one of the host's interfaces in any network.
func (h *HostState) Interface(id model.InterfaceID) (*NetworkState, *Interface, bool) {
	for _, nid := range h.NetworkIDs() {
		n := h.Networks[nid]
		if i, ok := n.Interface(id); ok {
			return n, i, true
		}
	}
	return nil, nil, false
}
