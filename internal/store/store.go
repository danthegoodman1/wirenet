//wirenet:deterministic

// Package store defines the control plane's records and the transactional
// interface every database implements. The control plane's logic lives above
// it, once; a backend only stores and finds records.
package store

import (
	"context"
	"errors"
	"net/netip"
	"slices"
	"time"

	"github.com/danthegoodman1/wirenet/internal/api"
	"github.com/danthegoodman1/wirenet/internal/model"
)

// Errors every backend returns for the same conditions, so the control
// plane can tell them apart whatever the database.
var (
	// ErrNotFound reports a lookup that matched no record.
	ErrNotFound = errors.New("not found")
	// ErrConflict reports a put that would break a uniqueness rule: two
	// networks, hosts, relays or admins with one name, two services with
	// one name in a network, or two live interfaces holding one member name
	// of a service.
	ErrConflict = errors.New("conflict")
)

// Store is a transactional record store.
type Store interface {
	// Update runs fn in a serializable read-write transaction and commits
	// it if fn returns nil. A backend retries fn when the transaction
	// conflicts with another, so fn must have no effects outside tx. It
	// returns what the transaction touched.
	Update(ctx context.Context, fn func(Tx) error) (Change, error)
	// View runs fn over a consistent snapshot.
	View(ctx context.Context, fn func(ReadTx) error) error
}

// Change says what a committed transaction touched, so long polls for the
// hosts and relays it affects wake.
type Change struct {
	// Revision is the transaction's revision, zero if it bumped none.
	Revision uint64            `json:"revision,omitempty"`
	Networks []model.NetworkID `json:"networks,omitempty"`
	Hosts    []model.HostID    `json:"hosts,omitempty"`
	Relays   []model.RelayID   `json:"relays,omitempty"`
}

// Empty reports whether the change touched nothing.
func (c Change) Empty() bool {
	return len(c.Networks) == 0 && len(c.Hosts) == 0 && len(c.Relays) == 0
}

// Merge adds other's touches to c, keeping each list sorted and unique.
func (c *Change) Merge(other Change) {
	c.Revision = max(c.Revision, other.Revision)
	c.Networks = union(c.Networks, other.Networks)
	c.Hosts = union(c.Hosts, other.Hosts)
	c.Relays = union(c.Relays, other.Relays)
}

func union[T ~string](a, b []T) []T {
	out := slices.Concat(a, b)
	slices.Sort(out)
	return slices.Compact(out)
}

// ReadTx finds records. Every list comes back sorted by identifier, and a
// limit of zero or less lists every match.
type ReadTx interface {
	Network(model.NetworkID) (Network, error)
	NetworkByName(name string) (Network, error)
	Networks() ([]Network, error)

	Service(model.ServiceID) (Service, error)
	ServiceByName(net model.NetworkID, name string) (Service, error)
	Services(model.NetworkID) ([]Service, error)

	Interface(model.InterfaceID) (Interface, error)
	// Interfaces lists a network's interfaces in every state.
	Interfaces(model.NetworkID) ([]Interface, error)
	// HostInterfaces lists a host's interfaces in every state.
	HostInterfaces(model.HostID) ([]Interface, error)
	// Holder finds the live interface holding a member name of a service.
	Holder(svc model.ServiceID, member string) (Interface, error)
	// Expired lists up to limit live interfaces whose lease expired before
	// t, soonest expiry first.
	Expired(t time.Time, limit int) ([]Interface, error)
	// Undrained lists up to limit released interfaces still draining that
	// ended before t, oldest first.
	Undrained(t time.Time, limit int) ([]Interface, error)
	// Ended lists up to limit drained interfaces that ended before t,
	// oldest first.
	Ended(t time.Time, limit int) ([]Interface, error)

	Rule(model.RuleID) (Rule, error)
	Rules(model.NetworkID) ([]Rule, error)

	// Edges lists a network's edges, sorted by their pair.
	Edges(model.NetworkID) ([]Edge, error)
	// RelayEdges lists every edge holding ports on a relay.
	RelayEdges(model.RelayID) ([]Edge, error)
	// DormantEdges lists up to limit edges dormant since before t, oldest
	// first.
	DormantEdges(t time.Time, limit int) ([]Edge, error)

	Host(model.HostID) (Host, error)
	HostByName(name string) (Host, error)
	HostByToken(hash [32]byte) (Host, error)
	Hosts() ([]Host, error)

	Admin(model.AdminID) (Admin, error)
	AdminByName(name string) (Admin, error)
	AdminByToken(hash [32]byte) (Admin, error)
	Admins() ([]Admin, error)

	Relay(model.RelayID) (Relay, error)
	RelayByName(name string) (Relay, error)
	RelayByToken(hash [32]byte) (Relay, error)
	Relays() ([]Relay, error)

	// Released4 lists up to limit quarantined IPv4 addresses of a network
	// released before t, oldest first.
	Released4(net model.NetworkID, before time.Time, limit int) ([]Released4, error)
	// ReleasedPorts lists up to limit quarantined ports on one relay address
	// released before t, oldest first.
	ReleasedPorts(relay model.RelayID, addr netip.Addr, before time.Time, limit int) ([]ReleasedPort, error)
	// PortCursor returns the next never-used port on a relay address, zero
	// before the first allocation.
	PortCursor(relay model.RelayID, addr netip.Addr) (uint16, error)

	// Meta reads a small value the control plane keeps for itself.
	Meta(key string) (string, bool, error)
}

// Tx changes records. Puts insert or replace by identifier.
type Tx interface {
	ReadTx

	PutNetwork(Network) error
	DeleteNetwork(model.NetworkID) error
	PutService(Service) error
	DeleteService(model.ServiceID) error
	PutInterface(Interface) error
	DeleteInterface(model.InterfaceID) error
	PutRule(Rule) error
	DeleteRule(model.RuleID) error
	PutEdge(Edge) error
	DeleteEdge(net model.NetworkID, a, b model.InterfaceID) error
	PutHost(Host) error
	// DeleteHost removes a host, and with it its token.
	DeleteHost(model.HostID) error
	PutRelay(Relay) error
	// DeleteRelay removes a relay, its port cursors and its released
	// ports.
	DeleteRelay(model.RelayID) error
	PutAdmin(Admin) error
	// DeleteAdmin removes an admin, and with it its token.
	DeleteAdmin(model.AdminID) error

	PutReleased4(Released4) error
	DeleteReleased4(net model.NetworkID, addr netip.Addr) error
	PutReleasedPort(ReleasedPort) error
	DeleteReleasedPort(relay model.RelayID, addr netip.Addr, port uint16) error
	SetPortCursor(relay model.RelayID, addr netip.Addr, next uint16) error

	SetMeta(key, value string) error

	// Bump returns a revision greater than every revision any transaction
	// committed before this one, and the same value on every call within
	// this transaction.
	Bump() (uint64, error)
	// Touch records what the transaction changed.
	Touch(Change)
}

// Network is an address space.
type Network struct {
	ID      model.NetworkID `json:"id"`
	Name    string          `json:"name"`
	Prefix6 netip.Prefix    `json:"prefix6"`
	Prefix4 netip.Prefix    `json:"prefix4,omitzero"`
	MTU     int             `json:"mtu"`
	// Relays is the relay set, in preference order.
	Relays []model.RelayID `json:"relays,omitempty"`
	// Next6 and Next4 are the next never-used host index in each family.
	Next6    uint64    `json:"next6"`
	Next4    uint64    `json:"next4"`
	Revision uint64    `json:"revision"`
	Created  time.Time `json:"created"`
	// Changed is when the revision last moved: the commit time agents
	// measure convergence from.
	Changed time.Time `json:"changed,omitzero"`
	// Quota bounds what the network may hold.
	Quota api.Quota `json:"quota,omitzero"`
}

// Service is a stable name and address in a network.
type Service struct {
	ID      model.ServiceID `json:"id"`
	Network model.NetworkID `json:"network"`
	Name    string          `json:"name"`
	IPv4    bool            `json:"ipv4"`
	Addr6   netip.Addr      `json:"addr6"`
	Addr4   netip.Addr      `json:"addr4,omitzero"`
	Mode    api.Mode        `json:"mode"`
	Created time.Time       `json:"created"`
}

// Interface is one attachment and its lease.
type Interface struct {
	ID      model.InterfaceID `json:"id"`
	Network model.NetworkID   `json:"network"`
	Service model.ServiceID   `json:"service"`
	Host    model.HostID      `json:"host"`
	Kind    api.Kind          `json:"kind"`
	// Gateway is the gateway interface a device reaches the network
	// through.
	Gateway    model.InterfaceID `json:"gateway,omitempty"`
	PublicKey  model.Key         `json:"public_key"`
	Addr6      netip.Addr        `json:"addr6"`
	Addr4      netip.Addr        `json:"addr4,omitzero"`
	ListenPort uint16            `json:"listen_port"`
	State      api.LeaseState    `json:"state"`
	Expires    time.Time         `json:"expires"`
	Created    time.Time         `json:"created"`
	// Ended is when the interface was released or revoked.
	Ended time.Time `json:"ended,omitzero"`
	// Drained marks an ended interface whose peers no longer hold it: a
	// revoked one at once, a released one once its grace period ends.
	Drained bool `json:"drained,omitempty"`
	// Member is a name among its service's members, which the interface
	// holds while it is live.
	Member string `json:"member,omitempty"`
}

// Rule allows or denies flows from a service to a service or the internet.
// Either side may be every service.
type Rule struct {
	ID      model.RuleID    `json:"id"`
	Network model.NetworkID `json:"network"`
	// From is a service or model.AnyService.
	From model.ServiceID `json:"from"`
	// To is a service, model.AnyService, or empty for internet egress.
	To      model.ServiceID `json:"to,omitempty"`
	Proto   model.Proto     `json:"proto"`
	Ports   model.PortRange `json:"ports"`
	Created time.Time       `json:"created"`
	// Deny takes the flows the rule names out of every allow.
	Deny bool `json:"deny,omitempty"`
}

// Edge is a pair of policy-connected interfaces on different hosts, with a
// port for each direction on every relay of the network's set. A is the
// lesser identifier.
type Edge struct {
	Network model.NetworkID   `json:"network"`
	A       model.InterfaceID `json:"a"`
	B       model.InterfaceID `json:"b"`
	// SecretAB and SecretBA are each direction's registration secret.
	SecretAB model.Secret `json:"secret_ab"`
	SecretBA model.Secret `json:"secret_ba"`
	Ports    []EdgePorts  `json:"ports"`
	Created  time.Time    `json:"created"`
	// Dormant is when policy stopped connecting a pair that is still
	// attached. A dormant edge keeps its ports and secrets for the port
	// quarantine, so a pair that reconnects gets the same edge back.
	Dormant time.Time `json:"dormant,omitzero"`
}

// EdgePorts are an edge's two ports on one relay address.
type EdgePorts struct {
	Relay model.RelayID `json:"relay"`
	// Addr is the relay's local address the ports are bound on.
	Addr netip.Addr `json:"addr"`
	AB   uint16     `json:"ab"`
	BA   uint16     `json:"ba"`
}

// Scope is the networks a token admits: every network, or those listed. A
// list emptied by deleted networks admits none, so a scope never widens on
// its own.
type Scope struct {
	Global   bool              `json:"global,omitempty"`
	Networks []model.NetworkID `json:"networks,omitempty"`
}

// Admits reports whether the scope admits a network.
func (s Scope) Admits(n model.NetworkID) bool {
	return s.Global || slices.Contains(s.Networks, n)
}

// Without returns the scope with a network taken out, and whether it held
// it. A list emptied this way is nil and admits nothing.
func (s Scope) Without(n model.NetworkID) (Scope, bool) {
	i := slices.Index(s.Networks, n)
	if i < 0 {
		return s, false
	}
	s.Networks = slices.Delete(slices.Clone(s.Networks), i, i+1)
	if len(s.Networks) == 0 {
		s.Networks = nil
	}
	return s, true
}

// Within reports whether every network s admits, o admits too.
func (s Scope) Within(o Scope) bool {
	if o.Global {
		return true
	}
	if s.Global {
		return false
	}
	for _, n := range s.Networks {
		if !slices.Contains(o.Networks, n) {
			return false
		}
	}
	return true
}

// Host is a machine running an agent.
type Host struct {
	ID        model.HostID   `json:"id"`
	Name      string         `json:"name"`
	TokenHash [32]byte       `json:"token_hash"`
	Endpoint  netip.AddrPort `json:"endpoint,omitzero"`
	// Scope is the networks the host may attach interfaces into.
	Scope Scope `json:"scope"`
	// Revision is the last revision that changed which interfaces the host
	// holds.
	Revision uint64    `json:"revision"`
	Created  time.Time `json:"created"`
}

// Admin is a token that manages the networks its scope admits. The
// operator's own token is configured rather than stored, and is the only
// global one.
type Admin struct {
	ID        model.AdminID `json:"id"`
	Name      string        `json:"name"`
	TokenHash [32]byte      `json:"token_hash"`
	Scope     Scope         `json:"scope"`
	Created   time.Time     `json:"created"`
}

// Relay is a ciphertext forwarder.
type Relay struct {
	ID        model.RelayID      `json:"id"`
	Name      string             `json:"name"`
	TokenHash [32]byte           `json:"token_hash"`
	Addresses []api.RelayAddress `json:"addresses"`
	PortLo    uint16             `json:"port_lo"`
	PortHi    uint16             `json:"port_hi"`
	ProbePort uint16             `json:"probe_port"`
	// Revision is the last revision that changed the relay's port table.
	Revision uint64    `json:"revision"`
	Created  time.Time `json:"created"`
}

// Released4 is a quarantined IPv4 address.
type Released4 struct {
	Network model.NetworkID `json:"network"`
	Addr    netip.Addr      `json:"addr"`
	At      time.Time       `json:"at"`
}

// ReleasedPort is a quarantined relay port.
type ReleasedPort struct {
	Relay model.RelayID `json:"relay"`
	Addr  netip.Addr    `json:"addr"`
	Port  uint16        `json:"port"`
	At    time.Time     `json:"at"`
}
