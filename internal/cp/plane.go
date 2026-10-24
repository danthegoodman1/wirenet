//wirenet:deterministic

// Package cp is the control plane's logic: allocation, leases, policy and
// edges, as transitions over a store transaction. It reads no clock and draws
// randomness only from the source it is given, so the simulator runs the
// same transitions a daemon does.
package cp

import (
	"crypto/sha256"
	"encoding/base64"
	"errors"
	"fmt"
	"io"
	"net/netip"
	"slices"
	"strings"
	"time"

	"github.com/danthegoodman1/wirenet/internal/api"
	"github.com/danthegoodman1/wirenet/internal/model"
	"github.com/danthegoodman1/wirenet/internal/store"
)

// Config holds the control plane's clocks.
type Config struct {
	// LeaseTTL is how long a lease lasts unless renewed.
	LeaseTTL time.Duration
	// DrainGrace is how long peers keep a released interface installed, so
	// its established connections finish.
	DrainGrace time.Duration
	// Quarantine4 is how long an IPv4 address waits for reuse once its
	// interface drains, so agents converge on its departure first. It runs
	// from the drain rather than the release: a control plane that was
	// down drains late, and peers route the address until it does.
	Quarantine4 time.Duration
	// PortQuarantine is how long a released relay port waits before reuse,
	// so a stale sender's packets stop arriving first.
	PortQuarantine time.Duration
	// Retention is how long an ended interface stays visible to its own
	// host, so the host learns its state.
	Retention time.Duration
	// MTU is a new network's overlay MTU unless it names one.
	MTU int
	// Quota bounds a new network unless it names its own.
	Quota api.Quota
}

// DefaultConfig returns the production clocks.
func DefaultConfig() Config {
	return Config{
		LeaseTTL:       30 * time.Second,
		DrainGrace:     30 * time.Second,
		Quarantine4:    2 * time.Minute,
		PortQuarantine: 5 * time.Minute,
		Retention:      10 * time.Minute,
		MTU:            1380,
	}
}

// Validate checks that the clocks keep their promises to each other.
func (c Config) Validate() error {
	switch {
	case c.LeaseTTL <= 0 || c.DrainGrace <= 0:
		return errors.New("lease TTL and drain grace must be positive")
	case c.PortQuarantine <= 0:
		return errors.New("port quarantine must be positive, or a stale sender reaches the next edge on its port")
	case c.Quarantine4 <= 0:
		return errors.New("IPv4 quarantine must be positive, or an address reaches a new owner before agents drop the old")
	case c.Retention < c.DrainGrace:
		return errors.New("retention must cover the drain grace period")
	case c.MTU < 1280:
		return errors.New("MTU must be at least 1280, the IPv6 minimum")
	case validQuota(c.Quota) != nil:
		return errors.New("a default quota's bounds are zero, for none, or positive")
	}
	return nil
}

// Plane carries out control-plane transitions.
type Plane struct {
	Config Config
	// Rand supplies identifiers, prefixes, secrets and tokens.
	Rand io.Reader
}

// Meta keys.
const (
	metaHeartbeat     = "heartbeat"
	metaExpiryResumes = "expiry_resumes"
)

// First host indexes handed out in each family. IPv6 keeps the low 256
// addresses of a network's /64 for its own infrastructure.
const (
	first6 = 0x100
	first4 = 1
)

func apiErr(code, format string, args ...any) error {
	return &api.Error{Code: code, Message: fmt.Sprintf(format, args...)}
}

// notFound turns a store miss into an API error naming what was missing.
func notFound(err error, what string) error {
	if errors.Is(err, store.ErrNotFound) {
		return apiErr(api.CodeNotFound, "%s not found", what)
	}
	return err
}

func conflict(err error, what string) error {
	if errors.Is(err, store.ErrConflict) {
		return apiErr(api.CodeConflict, "%s already exists", what)
	}
	return err
}

// ValidName reports whether s is a lowercase DNS label.
func ValidName(s string) bool {
	if len(s) == 0 || len(s) > 63 || s[0] == '-' || s[len(s)-1] == '-' {
		return false
	}
	for i := 0; i < len(s); i++ {
		c := s[i]
		if !(c >= 'a' && c <= 'z' || c >= '0' && c <= '9' || c == '-') {
			return false
		}
	}
	return true
}

func (p *Plane) id(prefix string) (string, error) {
	return model.NewID(prefix, p.Rand)
}

// HashToken returns what the store keeps of a bearer token.
func HashToken(token string) [32]byte { return sha256.Sum256([]byte(token)) }

func (p *Plane) token() (string, [32]byte, error) {
	var b [32]byte
	if _, err := io.ReadFull(p.Rand, b[:]); err != nil {
		return "", [32]byte{}, err
	}
	t := base64.RawURLEncoding.EncodeToString(b[:])
	return t, HashToken(t), nil
}

// bump gives the network, and the hosts whose interface set changed, this
// transaction's revision, stamps the network with the time, and records
// the touch.
func bump(tx store.Tx, now time.Time, n *store.Network, hosts ...model.HostID) error {
	rev, err := tx.Bump()
	if err != nil {
		return err
	}
	n.Revision, n.Changed = rev, now
	if err := tx.PutNetwork(*n); err != nil {
		return err
	}
	tx.Touch(store.Change{Networks: []model.NetworkID{n.ID}})
	return bumpHosts(tx, hosts)
}

// bumpHosts gives hosts whose poll answer changed this transaction's
// revision, and records the touch.
func bumpHosts(tx store.Tx, hosts []model.HostID) error {
	if len(hosts) == 0 {
		return nil
	}
	rev, err := tx.Bump()
	if err != nil {
		return err
	}
	for _, id := range hosts {
		h, err := tx.Host(id)
		if err != nil {
			return notFound(err, "host "+string(id))
		}
		h.Revision = rev
		if err := tx.PutHost(h); err != nil {
			return err
		}
	}
	tx.Touch(store.Change{Hosts: hosts})
	return nil
}

// ResolveNetwork finds a network by identifier or name.
func ResolveNetwork(tx store.ReadTx, ref string) (store.Network, error) {
	var n store.Network
	var err error
	if strings.HasPrefix(ref, model.NetworkPrefix) {
		n, err = tx.Network(model.NetworkID(ref))
	} else {
		n, err = tx.NetworkByName(ref)
	}
	return n, notFound(err, "network "+ref)
}

// ResolveHost finds a host by name, or failing that by identifier.
func ResolveHost(tx store.ReadTx, ref string) (store.Host, error) {
	h, err := tx.HostByName(ref)
	if errors.Is(err, store.ErrNotFound) && strings.HasPrefix(ref, model.HostPrefix) {
		h, err = tx.Host(model.HostID(ref))
	}
	return h, notFound(err, "host "+ref)
}

// ResolveRelay finds a relay by name, or failing that by identifier.
func ResolveRelay(tx store.ReadTx, ref string) (store.Relay, error) {
	r, err := tx.RelayByName(ref)
	if errors.Is(err, store.ErrNotFound) && strings.HasPrefix(ref, model.RelayPrefix) {
		r, err = tx.Relay(model.RelayID(ref))
	}
	return r, notFound(err, "relay "+ref)
}

// ResolveService finds a service of a network by identifier or name.
func ResolveService(tx store.ReadTx, net model.NetworkID, ref string) (store.Service, error) {
	if strings.HasPrefix(ref, model.ServicePrefix) {
		s, err := tx.Service(model.ServiceID(ref))
		if err == nil && s.Network != net {
			err = store.ErrNotFound
		}
		return s, notFound(err, "service "+ref)
	}
	s, err := tx.ServiceByName(net, ref)
	return s, notFound(err, "service "+ref)
}

// CreateNetwork creates an address space.
func (p *Plane) CreateNetwork(tx store.Tx, now time.Time, req api.CreateNetwork) (store.Network, error) {
	if !ValidName(req.Name) {
		return store.Network{}, apiErr(api.CodeInvalid, "network name %q is not a DNS label", req.Name)
	}
	prefix6 := req.Prefix6
	if !prefix6.IsValid() {
		var b [16]byte
		b[0] = 0xfd
		if _, err := io.ReadFull(p.Rand, b[1:6]); err != nil {
			return store.Network{}, err
		}
		prefix6 = netip.PrefixFrom(netip.AddrFrom16(b), 64)
	}
	if !prefix6.Addr().Is6() || prefix6.Addr().Is4In6() || prefix6.Bits() != 64 || prefix6.Masked() != prefix6 {
		return store.Network{}, apiErr(api.CodeInvalid, "IPv6 prefix %s must be a /64", prefix6)
	}
	if req.Prefix4.IsValid() {
		if !req.Prefix4.Addr().Is4() || req.Prefix4.Bits() < 8 || req.Prefix4.Bits() > 30 || req.Prefix4.Masked() != req.Prefix4 {
			return store.Network{}, apiErr(api.CodeInvalid, "IPv4 prefix %s must be between /8 and /30", req.Prefix4)
		}
	}
	mtu := req.MTU
	if mtu == 0 {
		mtu = p.Config.MTU
	}
	if mtu < 1280 || mtu > 9000 {
		return store.Network{}, apiErr(api.CodeInvalid, "MTU %d must be between 1280 and 9000", mtu)
	}
	for _, r := range req.Relays {
		if _, err := tx.Relay(r); err != nil {
			return store.Network{}, notFound(err, "relay "+string(r))
		}
	}
	if err := validQuota(req.Quota); err != nil {
		return store.Network{}, err
	}
	quota := mergeQuota(req.Quota, p.Config.Quota)
	id, err := p.id(model.NetworkPrefix)
	if err != nil {
		return store.Network{}, err
	}
	n := store.Network{
		ID:      model.NetworkID(id),
		Name:    req.Name,
		Prefix6: prefix6,
		Prefix4: req.Prefix4,
		MTU:     mtu,
		Relays:  req.Relays,
		Next6:   first6,
		Next4:   first4,
		Created: now,
		Quota:   quota,
	}
	if err := tx.PutNetwork(n); err != nil {
		return store.Network{}, conflict(err, "network "+req.Name)
	}
	return n, bump(tx, now, &n)
}

// DeleteNetwork removes a network with nothing connected to it.
func (p *Plane) DeleteNetwork(tx store.Tx, ref string) error {
	n, err := ResolveNetwork(tx, ref)
	if err != nil {
		return err
	}
	ifaces, err := tx.Interfaces(n.ID)
	if err != nil {
		return err
	}
	for _, i := range ifaces {
		if i.State == api.Live || !i.Drained {
			return apiErr(api.CodeConflict, "network %s still has interface %s", n.Name, i.ID)
		}
	}
	var hosts []model.HostID
	for _, i := range ifaces {
		if err := tx.DeleteInterface(i.ID); err != nil {
			return err
		}
		hosts = append(hosts, i.Host)
	}
	rules, err := tx.Rules(n.ID)
	if err != nil {
		return err
	}
	for _, r := range rules {
		if err := tx.DeleteRule(r.ID); err != nil {
			return err
		}
	}
	svcs, err := tx.Services(n.ID)
	if err != nil {
		return err
	}
	for _, s := range svcs {
		if err := tx.DeleteService(s.ID); err != nil {
			return err
		}
	}
	// The hosts that still saw the network's ended interfaces move to a
	// generation that no longer lists it, so they drop it.
	slices.Sort(hosts)
	if err := bumpHosts(tx, slices.Compact(hosts)); err != nil {
		return err
	}
	if err := dropFromScopes(tx, n.ID); err != nil {
		return err
	}
	tx.Touch(store.Change{Networks: []model.NetworkID{n.ID}})
	return tx.DeleteNetwork(n.ID)
}

// CreateService declares a service and gives it its addresses, in a
// network the scope by admits.
func (p *Plane) CreateService(tx store.Tx, now time.Time, by store.Scope, netRef string, req api.CreateService) (store.Service, error) {
	n, err := ResolveNetworkIn(tx, by, netRef)
	if err != nil {
		return store.Service{}, err
	}
	if !ValidName(req.Name) || req.Name == api.Internet {
		return store.Service{}, apiErr(api.CodeInvalid, "service name %q is not a DNS label", req.Name)
	}
	mode := req.Mode
	if mode == "" {
		mode = api.Flip
	}
	if mode != api.Flip && mode != api.Cutover {
		return store.Service{}, apiErr(api.CodeInvalid, "mode %q must be flip or cutover", mode)
	}
	if _, err := tx.ServiceByName(n.ID, req.Name); err == nil {
		return store.Service{}, apiErr(api.CodeConflict, "service %s already exists", req.Name)
	}
	// Only a bounded network pays for the count.
	if n.Quota.Services > 0 {
		svcs, err := tx.Services(n.ID)
		if err != nil {
			return store.Service{}, err
		}
		if err := overQuota("services", n.Quota.Services, len(svcs), len(svcs)+1); err != nil {
			return store.Service{}, err
		}
	}
	id, err := p.id(model.ServicePrefix)
	if err != nil {
		return store.Service{}, err
	}
	s := store.Service{ID: model.ServiceID(id), Network: n.ID, Name: req.Name, IPv4: req.IPv4, Mode: mode, Created: now}
	s.Addr6 = alloc6(&n)
	if req.IPv4 {
		if s.Addr4, err = p.alloc4(tx, &n, now); err != nil {
			return store.Service{}, err
		}
	}
	if err := tx.PutService(s); err != nil {
		return store.Service{}, conflict(err, "service "+req.Name)
	}
	return s, bump(tx, now, &n)
}

// DeleteService removes a service with no connected interfaces, and the
// rules naming it.
func (p *Plane) DeleteService(tx store.Tx, now time.Time, by store.Scope, netRef, ref string) error {
	n, err := ResolveNetworkIn(tx, by, netRef)
	if err != nil {
		return err
	}
	s, err := ResolveService(tx, n.ID, ref)
	if err != nil {
		return err
	}
	ifaces, err := tx.Interfaces(n.ID)
	if err != nil {
		return err
	}
	for _, i := range ifaces {
		if i.Service == s.ID && (i.State == api.Live || !i.Drained) {
			return apiErr(api.CodeConflict, "service %s still has interface %s", s.Name, i.ID)
		}
	}
	rules, err := tx.Rules(n.ID)
	if err != nil {
		return err
	}
	for _, r := range rules {
		if r.From == s.ID || r.To == s.ID {
			if err := tx.DeleteRule(r.ID); err != nil {
				return err
			}
		}
	}
	if s.Addr4.IsValid() {
		if err := tx.PutReleased4(store.Released4{Network: n.ID, Addr: s.Addr4, At: now}); err != nil {
			return err
		}
	}
	if err := tx.DeleteService(s.ID); err != nil {
		return err
	}
	return bump(tx, now, &n)
}

// CreateRule allows or denies flows from a service, or every service, to a
// service, every service, or the internet.
func (p *Plane) CreateRule(tx store.Tx, now time.Time, by store.Scope, netRef string, req api.CreateRule) (store.Rule, error) {
	n, err := ResolveNetworkIn(tx, by, netRef)
	if err != nil {
		return store.Rule{}, err
	}
	// A rule to the internet sends traffic out from the host's own
	// addresses, which on a shared host are the operator's, so a scoped
	// caller may narrow egress and never widen it.
	if req.To == api.Internet && req.Action != api.Deny && !by.Global {
		return store.Rule{}, apiErr(api.CodeForbidden, "only the operator grants internet egress")
	}
	action := req.Action
	if action == "" {
		action = api.Allow
	}
	if action != api.Allow && action != api.Deny {
		return store.Rule{}, apiErr(api.CodeInvalid, "action %q must be allow or deny", req.Action)
	}
	if req.From == api.Internet {
		return store.Rule{}, apiErr(api.CodeInvalid, "the internet is a destination only")
	}
	from, err := ruleSide(tx, n.ID, req.From)
	if err != nil {
		return store.Rule{}, err
	}
	var to model.ServiceID
	if req.To != api.Internet {
		if to, err = ruleSide(tx, n.ID, req.To); err != nil {
			return store.Rule{}, err
		}
	}
	if !req.Proto.Valid() {
		return store.Rule{}, apiErr(api.CodeInvalid, "protocol %q must be tcp, udp or any", req.Proto)
	}
	if req.Proto == model.AnyProto && !req.Ports.All() {
		return store.Rule{}, apiErr(api.CodeInvalid, "a rule for any protocol takes no ports")
	}
	if !req.Ports.All() && (req.Ports.Lo == 0 || req.Ports.Hi < req.Ports.Lo) {
		return store.Rule{}, apiErr(api.CodeInvalid, "bad port range %s", req.Ports)
	}
	rules, err := tx.Rules(n.ID)
	if err != nil {
		return store.Rule{}, err
	}
	deny := action == api.Deny
	for _, r := range rules {
		if r.From == from && r.To == to && r.Proto == req.Proto && r.Ports == req.Ports && r.Deny == deny {
			return r, nil
		}
	}
	if err := overQuota("rules", n.Quota.Rules, len(rules), len(rules)+1); err != nil {
		return store.Rule{}, err
	}
	id, err := p.id(model.RulePrefix)
	if err != nil {
		return store.Rule{}, err
	}
	r := store.Rule{ID: model.RuleID(id), Network: n.ID, From: from, To: to, Proto: req.Proto, Ports: req.Ports, Created: now, Deny: deny}
	if err := tx.PutRule(r); err != nil {
		return store.Rule{}, err
	}
	if to != "" {
		h, err := p.reconcileEdges(tx, now, &n, ruleScope(r))
		if err != nil {
			return store.Rule{}, err
		}
		if err := overQuota("edges", n.Quota.Edges, h.edgesBefore, h.edgesAfter); err != nil {
			return store.Rule{}, err
		}
	}
	return r, bump(tx, now, &n)
}

// ruleSide resolves one side of a rule: a service, or every service.
func ruleSide(tx store.ReadTx, net model.NetworkID, ref string) (model.ServiceID, error) {
	if ref == api.Wildcard {
		return model.AnyService, nil
	}
	svc, err := ResolveService(tx, net, ref)
	return svc.ID, err
}

// DeleteRule removes a rule, and the edges no other rule keeps.
func (p *Plane) DeleteRule(tx store.Tx, now time.Time, by store.Scope, netRef string, id model.RuleID) error {
	n, err := ResolveNetworkIn(tx, by, netRef)
	if err != nil {
		return err
	}
	r, err := tx.Rule(id)
	if err != nil {
		return notFound(err, "rule "+string(id))
	}
	if r.Network != n.ID {
		return notFound(store.ErrNotFound, "rule "+string(id))
	}
	if r.To == "" && r.Deny && !by.Global {
		return apiErr(api.CodeForbidden, "only the operator lifts a deny on internet egress")
	}
	if err := tx.DeleteRule(id); err != nil {
		return err
	}
	// Deleting a deny connects what it held apart, so it can add edges.
	if r.To != "" {
		h, err := p.reconcileEdges(tx, now, &n, ruleScope(r))
		if err != nil {
			return err
		}
		if err := overQuota("edges", n.Quota.Edges, h.edgesBefore, h.edgesAfter); err != nil {
			return err
		}
	}
	return bump(tx, now, &n)
}

// CreateHost registers a host and returns its token. A host the request
// scopes to networks may attach only into them, each within the scope by
// of the principal registering it; a host given none is global, which only
// a global principal registers.
func (p *Plane) CreateHost(tx store.Tx, now time.Time, by store.Scope, req api.CreateHost) (store.Host, string, error) {
	if !ValidName(req.Name) {
		return store.Host{}, "", apiErr(api.CodeInvalid, "host name %q is not a DNS label", req.Name)
	}
	sc, err := hostScope(tx, by, api.Scope{Global: len(req.Networks) == 0, Networks: req.Networks})
	if err != nil {
		return store.Host{}, "", err
	}
	id, err := p.id(model.HostPrefix)
	if err != nil {
		return store.Host{}, "", err
	}
	token, hash, err := p.token()
	if err != nil {
		return store.Host{}, "", err
	}
	h := store.Host{ID: model.HostID(id), Name: req.Name, TokenHash: hash, Endpoint: req.Endpoint, Scope: sc, Created: now}
	if err := tx.PutHost(h); err != nil {
		return store.Host{}, "", conflict(err, "host "+req.Name)
	}
	return h, token, nil
}

// DeleteHost removes a host and its token. It revokes every interface the
// host holds, which ends the development machines behind its gateways too,
// and deletes their records with the host's, since no host is left to learn
// their state.
func (p *Plane) DeleteHost(tx store.Tx, now time.Time, by store.Scope, ref string) (store.Host, error) {
	h, err := ResolveHostIn(tx, by, ref)
	if err != nil {
		return store.Host{}, err
	}
	ifaces, err := tx.HostInterfaces(h.ID)
	if err != nil {
		return store.Host{}, err
	}
	for _, i := range ifaces {
		if err := p.Revoke(tx, now, i.ID); err != nil {
			return store.Host{}, err
		}
	}
	var nets []model.NetworkID
	for _, i := range ifaces {
		if err := tx.DeleteInterface(i.ID); err != nil {
			return store.Host{}, err
		}
		nets = append(nets, i.Network)
	}
	// A network's revision moves with every record its compilation reads.
	slices.Sort(nets)
	for _, id := range slices.Compact(nets) {
		n, err := tx.Network(id)
		if err != nil {
			return store.Host{}, err
		}
		if err := bump(tx, now, &n); err != nil {
			return store.Host{}, err
		}
	}
	tx.Touch(store.Change{Hosts: []model.HostID{h.ID}})
	return h, tx.DeleteHost(h.ID)
}

// CreateRelay registers a relay and returns its token.
func (p *Plane) CreateRelay(tx store.Tx, now time.Time, req api.CreateRelay) (store.Relay, string, error) {
	if !ValidName(req.Name) {
		return store.Relay{}, "", apiErr(api.CodeInvalid, "relay name %q is not a DNS label", req.Name)
	}
	if len(req.Addresses) == 0 {
		return store.Relay{}, "", apiErr(api.CodeInvalid, "a relay needs an address")
	}
	for _, a := range req.Addresses {
		if !a.Local.IsValid() || !a.Advertised.IsValid() || a.Local.Is4() != a.Advertised.Is4() {
			return store.Relay{}, "", apiErr(api.CodeInvalid, "relay address %v needs a local and an advertised address of one family", a)
		}
	}
	// A port range ending at 65534 leaves the allocation cursor room to
	// pass its end without wrapping.
	if req.PortLo < 1024 || req.PortHi > 65534 || req.PortHi <= req.PortLo {
		return store.Relay{}, "", apiErr(api.CodeInvalid, "relay ports %d-%d must lie within 1024-65534", req.PortLo, req.PortHi)
	}
	if req.ProbePort == 0 || req.ProbePort >= req.PortLo && req.ProbePort <= req.PortHi {
		return store.Relay{}, "", apiErr(api.CodeInvalid, "probe port %d must lie outside the edge ports", req.ProbePort)
	}
	id, err := p.id(model.RelayPrefix)
	if err != nil {
		return store.Relay{}, "", err
	}
	token, hash, err := p.token()
	if err != nil {
		return store.Relay{}, "", err
	}
	// A revision from birth, so a relay's first poll, from generation zero,
	// always finds its table newer and every later one parks.
	rev, err := tx.Bump()
	if err != nil {
		return store.Relay{}, "", err
	}
	r := store.Relay{
		ID: model.RelayID(id), Name: req.Name, TokenHash: hash, Addresses: req.Addresses,
		PortLo: req.PortLo, PortHi: req.PortHi, ProbePort: req.ProbePort, Revision: rev, Created: now,
	}
	if err := tx.PutRelay(r); err != nil {
		return store.Relay{}, "", conflict(err, "relay "+req.Name)
	}
	return r, token, nil
}

// DeleteRelay removes a relay that no network names, and its token. Edges
// hold ports only on the relays of their network's set, so the relay serves
// none.
func (p *Plane) DeleteRelay(tx store.Tx, ref string) (store.Relay, error) {
	r, err := ResolveRelay(tx, ref)
	if err != nil {
		return store.Relay{}, err
	}
	nets, err := tx.Networks()
	if err != nil {
		return store.Relay{}, err
	}
	for _, n := range nets {
		if slices.Contains(n.Relays, r.ID) {
			return store.Relay{}, apiErr(api.CodeConflict, "relay %s serves network %s", r.Name, n.Name)
		}
	}
	tx.Touch(store.Change{Relays: []model.RelayID{r.ID}})
	return r, tx.DeleteRelay(r.ID)
}

// Attach issues an interface and its lease to a host. The agent chose the
// interface's identifier, so attaching the same identifier again with the
// same key returns the interface already issued. An attach naming a member
// its service's live interface holds fails, unless it replaces the holder:
// Attach then revokes the holder and returns its identifier.
func (p *Plane) Attach(tx store.Tx, now time.Time, host model.HostID, req api.AttachRequest) (store.Interface, model.InterfaceID, error) {
	if !strings.HasPrefix(string(req.Interface), model.InterfacePrefix) || len(req.Interface) <= len(model.InterfacePrefix) {
		return store.Interface{}, "", apiErr(api.CodeInvalid, "interface identifier %q must start with %s", req.Interface, model.InterfacePrefix)
	}
	if req.PublicKey.IsZero() || req.ListenPort == 0 {
		return store.Interface{}, "", apiErr(api.CodeInvalid, "attach needs a public key and a listen port")
	}
	if existing, err := tx.Interface(req.Interface); err == nil {
		if existing.Host == host && existing.PublicKey == req.PublicKey && existing.State == api.Live {
			if existing.Member != req.Member {
				return store.Interface{}, "", apiErr(api.CodeConflict, "interface %s holds member %q, not %q", req.Interface, existing.Member, req.Member)
			}
			return existing, "", nil
		}
		return store.Interface{}, "", apiErr(api.CodeConflict, "interface %s already exists", req.Interface)
	} else if !errors.Is(err, store.ErrNotFound) {
		return store.Interface{}, "", err
	}
	kind := req.Kind
	if kind == "" {
		kind = api.Workload
	}
	if kind != api.Workload && kind != api.Gateway {
		return store.Interface{}, "", apiErr(api.CodeInvalid, "an agent attaches workloads and gateways, not %q", kind)
	}
	if req.Member != "" && (kind != api.Workload || !ValidName(req.Member)) {
		return store.Interface{}, "", apiErr(api.CodeInvalid, "member %q must be a DNS label, held by a workload", req.Member)
	}
	if req.Replace && req.Member == "" {
		return store.Interface{}, "", apiErr(api.CodeInvalid, "replace names the member it takes over")
	}
	h, err := tx.Host(host)
	if err != nil {
		return store.Interface{}, "", notFound(err, "host "+string(host))
	}
	n, err := ResolveNetworkIn(tx, h.Scope, req.Network)
	if err != nil {
		return store.Interface{}, "", err
	}
	svc, err := ResolveService(tx, n.ID, req.Service)
	if err != nil {
		return store.Interface{}, "", err
	}
	var replaced model.InterfaceID
	// edgesFrom is the edge count the quota check runs from. A replacement
	// counts from before its holder's revocation took its edges away.
	edgesFrom := -1
	if req.Member != "" {
		holder, err := tx.Holder(svc.ID, req.Member)
		switch {
		case errors.Is(err, store.ErrNotFound):
		case err != nil:
			return store.Interface{}, "", err
		case !req.Replace:
			return store.Interface{}, "", apiErr(api.CodeConflict, "member %s of %s is held by %s", req.Member, svc.Name, holder.ID)
		default:
			// Revoking removes the holder from every peer at once, so it
			// reaches nothing once hosts converge on this revision.
			gone, err := p.revoke(tx, now, holder.ID)
			if err != nil {
				return store.Interface{}, "", err
			}
			edgesFrom, replaced = gone.edgesBefore, holder.ID
			if n, err = tx.Network(n.ID); err != nil {
				return store.Interface{}, "", err
			}
		}
	}
	iface := store.Interface{
		ID:         req.Interface,
		Network:    n.ID,
		Service:    svc.ID,
		Host:       host,
		Kind:       kind,
		PublicKey:  req.PublicKey,
		ListenPort: req.ListenPort,
		State:      api.Live,
		Expires:    now.Add(p.Config.LeaseTTL),
		Created:    now,
		Member:     req.Member,
	}
	iface.Addr6 = alloc6(&n)
	if svc.IPv4 {
		if iface.Addr4, err = p.alloc4(tx, &n, now); err != nil {
			return store.Interface{}, "", err
		}
	}
	if err := tx.PutInterface(iface); err != nil {
		return store.Interface{}, "", err
	}
	held, err := p.reconcileEdges(tx, now, &n, interfaceScope(iface.ID))
	if err != nil {
		return store.Interface{}, "", err
	}
	// A replacement revoked its holder, so the interfaces it holds stay,
	// and its edges count from before the holder's went.
	if replaced == "" {
		if err := overQuota("live interfaces", n.Quota.Interfaces, held.live-1, held.live); err != nil {
			return store.Interface{}, "", err
		}
	}
	if edgesFrom < 0 {
		edgesFrom = held.edgesBefore
	}
	if err := overQuota("edges", n.Quota.Edges, edgesFrom, held.edgesAfter); err != nil {
		return store.Interface{}, "", err
	}
	return iface, replaced, bump(tx, now, &n, host)
}

// MaxDeviceTTL bounds a development machine's lease term.
const MaxDeviceTTL = 30 * 24 * time.Hour

// CreateDevice registers a development machine behind a gateway interface
// with a fixed-term lease. The caller minted the key and sends only its
// public half.
func (p *Plane) CreateDevice(tx store.Tx, now time.Time, by store.Scope, netRef string, req api.CreateDevice) (store.Interface, error) {
	n, err := ResolveNetworkIn(tx, by, netRef)
	if err != nil {
		return store.Interface{}, err
	}
	if req.PublicKey.IsZero() {
		return store.Interface{}, apiErr(api.CodeInvalid, "a device needs a public key")
	}
	if req.TTL <= 0 || req.TTL > MaxDeviceTTL {
		return store.Interface{}, apiErr(api.CodeInvalid, "a device's term must lie between zero and %v", MaxDeviceTTL)
	}
	svc, err := ResolveService(tx, n.ID, req.Service)
	if err != nil {
		return store.Interface{}, err
	}
	// An interface of another network reads as absent, as one outside a
	// caller's scope does.
	gw, err := tx.Interface(req.Gateway)
	if err == nil && gw.Network != n.ID {
		err = store.ErrNotFound
	}
	if err != nil {
		return store.Interface{}, notFound(err, "gateway "+string(req.Gateway))
	}
	if gw.Kind != api.Gateway || gw.State != api.Live {
		return store.Interface{}, apiErr(api.CodeInvalid, "%s is not a live gateway of network %s", gw.ID, n.Name)
	}
	h, err := tx.Host(gw.Host)
	if err != nil {
		return store.Interface{}, notFound(err, "host "+string(gw.Host))
	}
	if !h.Endpoint.IsValid() {
		return store.Interface{}, apiErr(api.CodeInvalid, "gateway %s's host has no endpoint development machines can reach", gw.ID)
	}
	id, err := p.id(model.InterfacePrefix)
	if err != nil {
		return store.Interface{}, err
	}
	d := store.Interface{
		ID: model.InterfaceID(id), Network: n.ID, Service: svc.ID, Host: gw.Host, Kind: api.Device, Gateway: gw.ID,
		PublicKey: req.PublicKey, State: api.Live, Expires: now.Add(req.TTL), Created: now,
	}
	d.Addr6 = alloc6(&n)
	// The gateway forwards for the device, so the device has IPv4 only
	// where both its service and its gateway do.
	if svc.IPv4 && gw.Addr4.IsValid() {
		if d.Addr4, err = p.alloc4(tx, &n, now); err != nil {
			return store.Interface{}, err
		}
	}
	if err := tx.PutInterface(d); err != nil {
		return store.Interface{}, err
	}
	held, err := p.reconcileEdges(tx, now, &n, interfaceScope(gw.ID))
	if err != nil {
		return store.Interface{}, err
	}
	if err := overQuota("live interfaces", n.Quota.Interfaces, held.live-1, held.live); err != nil {
		return store.Interface{}, err
	}
	if err := overQuota("edges", n.Quota.Edges, held.edgesBefore, held.edgesAfter); err != nil {
		return store.Interface{}, err
	}
	return d, bump(tx, now, &n, gw.Host)
}

// DeviceConfig returns what a development machine's WireGuard config needs.
func DeviceConfig(tx store.ReadTx, id model.InterfaceID) (api.DeviceConfig, error) {
	d, err := tx.Interface(id)
	if err != nil {
		return api.DeviceConfig{}, notFound(err, "device "+string(id))
	}
	if d.Kind != api.Device {
		return api.DeviceConfig{}, apiErr(api.CodeNotFound, "device %s not found", id)
	}
	n, err := tx.Network(d.Network)
	if err != nil {
		return api.DeviceConfig{}, err
	}
	gw, err := tx.Interface(d.Gateway)
	if err != nil {
		return api.DeviceConfig{}, notFound(err, "gateway "+string(d.Gateway))
	}
	h, err := tx.Host(gw.Host)
	if err != nil {
		return api.DeviceConfig{}, notFound(err, "host "+string(gw.Host))
	}
	// The host's endpoint names the address development machines reach;
	// its port, when set, is a port forwarded to the gateway's own.
	port := gw.ListenPort
	if h.Endpoint.Port() != 0 {
		port = h.Endpoint.Port()
	}
	c := api.DeviceConfig{
		Interface: d.ID, Addr6: d.Addr6, Addr4: d.Addr4, DNS: gw.Addr6,
		Domain: (&api.NetworkState{Name: n.Name}).Domain(), MTU: n.MTU,
		GatewayKey: gw.PublicKey, GatewayAddress: netip.AddrPortFrom(h.Endpoint.Addr(), port),
		Routes: []netip.Prefix{n.Prefix6}, Expires: d.Expires,
	}
	if d.Addr4.IsValid() && n.Prefix4.IsValid() {
		c.Routes = append(c.Routes, n.Prefix4)
	}
	return c, nil
}

// Release ends a host's interfaces as a planned removal: peers drain them
// over the grace period. Releasing an interface already ended, or one the
// host does not hold, changes nothing. A development machine is not its
// gateway host's to release: it ends by revocation, by its term, or with its
// gateway.
func (p *Plane) Release(tx store.Tx, now time.Time, host model.HostID, ids []model.InterfaceID) error {
	for _, id := range ids {
		i, err := tx.Interface(id)
		if errors.Is(err, store.ErrNotFound) {
			continue
		} else if err != nil {
			return err
		}
		if i.Host != host || i.State != api.Live || i.Kind == api.Device {
			continue
		}
		i.State, i.Ended = api.Released, now
		if _, err := p.end(tx, now, i, false); err != nil {
			return err
		}
	}
	return nil
}

// Revoke ends an interface at once: peers remove it with no grace period.
func (p *Plane) Revoke(tx store.Tx, now time.Time, id model.InterfaceID) error {
	_, err := p.revoke(tx, now, id)
	return err
}

// revoke is Revoke, returning what the network held around the edges the
// interface gave up.
func (p *Plane) revoke(tx store.Tx, now time.Time, id model.InterfaceID) (holdings, error) {
	i, err := tx.Interface(id)
	if err != nil {
		return holdings{}, notFound(err, "interface "+string(id))
	}
	if i.State == api.Revoked {
		return holdings{}, nil
	}
	if i.State == api.Live {
		i.Ended = now
	}
	// An address enters quarantine as its interface drains, which a
	// revocation does at once.
	quarantine := !i.Drained
	i.State, i.Drained = api.Revoked, true
	return p.end(tx, now, i, quarantine)
}

// end writes an interface that just left the live state, quarantines its
// IPv4 address if asked, revokes the development machines behind a gateway,
// drops its edges once it is drained, and bumps its network. It returns
// what the network held around the edges it dropped, and nothing for an
// interface still draining.
func (p *Plane) end(tx store.Tx, now time.Time, i store.Interface, quarantine bool) (holdings, error) {
	if quarantine && i.Addr4.IsValid() {
		if err := tx.PutReleased4(store.Released4{Network: i.Network, Addr: i.Addr4, At: now}); err != nil {
			return holdings{}, err
		}
	}
	if err := tx.PutInterface(i); err != nil {
		return holdings{}, err
	}
	if i.Kind == api.Gateway {
		if err := p.endDevices(tx, now, i); err != nil {
			return holdings{}, err
		}
	}
	n, err := tx.Network(i.Network)
	if err != nil {
		return holdings{}, err
	}
	var held holdings
	if i.Drained {
		if held, err = p.reconcileEdges(tx, now, &n, edgeScope(i)); err != nil {
			return holdings{}, err
		}
	}
	return held, bump(tx, now, &n, i.Host)
}

// endDevices revokes the development machines behind a gateway that just
// ended. A stock client holds one static peer and runs no agent, so nothing
// can move it to another gateway.
func (p *Plane) endDevices(tx store.Tx, now time.Time, gw store.Interface) error {
	ifaces, err := tx.HostInterfaces(gw.Host)
	if err != nil {
		return err
	}
	for _, d := range ifaces {
		if d.Kind == api.Device && d.Gateway == gw.ID && d.State == api.Live {
			if err := p.Revoke(tx, now, d.ID); err != nil {
				return err
			}
		}
	}
	return nil
}

// Renew extends the leases of a host's live interfaces and returns their
// new expiries. Interfaces it leaves out are no longer live.
func (p *Plane) Renew(tx store.Tx, now time.Time, host model.HostID, ids []model.InterfaceID) (map[model.InterfaceID]time.Time, error) {
	out := map[model.InterfaceID]time.Time{}
	for _, id := range ids {
		i, err := tx.Interface(id)
		if errors.Is(err, store.ErrNotFound) {
			continue
		} else if err != nil {
			return nil, err
		}
		// A development machine's lease has a fixed term; regenerating its
		// config extends it.
		if i.Host != host || i.State != api.Live || i.Kind == api.Device {
			continue
		}
		i.Expires = now.Add(p.Config.LeaseTTL)
		if err := tx.PutInterface(i); err != nil {
			return nil, err
		}
		out[id] = i.Expires
	}
	return out, nil
}

// SweepBatch bounds how much one sweep transaction changes.
const SweepBatch = 64

// Sweep revokes expired leases, ends drains whose grace period has passed,
// and deletes interfaces past retention. It reports how many interfaces it
// changed; a caller sweeps again while that is SweepBatch.
func (p *Plane) Sweep(tx store.Tx, now time.Time) (int, error) {
	changed := 0
	resumes, err := metaTime(tx, metaExpiryResumes)
	if err != nil {
		return 0, err
	}
	if !now.Before(resumes) {
		expired, err := tx.Expired(now, SweepBatch)
		if err != nil {
			return 0, err
		}
		for _, i := range expired {
			if err := p.Revoke(tx, now, i.ID); err != nil {
				return 0, err
			}
			changed++
		}
	}
	if changed >= SweepBatch {
		return changed, nil
	}
	draining, err := tx.Undrained(now.Add(-p.Config.DrainGrace), SweepBatch-changed)
	if err != nil {
		return 0, err
	}
	for _, i := range draining {
		i.Drained = true
		if err := tx.PutInterface(i); err != nil {
			return 0, err
		}
		if i.Addr4.IsValid() {
			if err := tx.PutReleased4(store.Released4{Network: i.Network, Addr: i.Addr4, At: now}); err != nil {
				return 0, err
			}
		}
		n, err := tx.Network(i.Network)
		if err != nil {
			return 0, err
		}
		if _, err := p.reconcileEdges(tx, now, &n, edgeScope(i)); err != nil {
			return 0, err
		}
		if err := bump(tx, now, &n, i.Host); err != nil {
			return 0, err
		}
		changed++
	}
	if changed >= SweepBatch {
		return changed, nil
	}
	n, err := p.expireDormant(tx, now, SweepBatch-changed)
	if err != nil {
		return 0, err
	}
	changed += n
	if changed >= SweepBatch {
		return changed, nil
	}
	old, err := tx.Ended(now.Add(-p.Config.Retention), SweepBatch-changed)
	if err != nil {
		return 0, err
	}
	for _, i := range old {
		if err := tx.DeleteInterface(i.ID); err != nil {
			return 0, err
		}
		n, err := tx.Network(i.Network)
		if err != nil {
			return 0, err
		}
		if err := bump(tx, now, &n, i.Host); err != nil {
			return 0, err
		}
		changed++
	}
	return changed, nil
}

// Boot runs when a control plane starts. Leases could not be renewed while
// it was down, so it holds off expiry for at least as long as it was down,
// and never less than one lease term, keeping a later hold already set. It
// returns how long it was down.
func (p *Plane) Boot(tx store.Tx, now time.Time) (time.Duration, error) {
	down, err := sinceHeartbeat(tx, now)
	if err != nil {
		return 0, err
	}
	if err := holdExpiry(tx, now.Add(max(down, p.Config.LeaseTTL))); err != nil {
		return 0, err
	}
	return down, setMetaTime(tx, metaHeartbeat, now)
}

// Heartbeat records that a control plane is up and reaching its store. A
// gap since the last heartbeat means the control plane or its store was
// down, and agents could not renew through it. A lease its agent keeps
// renewing has at least two thirds of a term left, so any gap over a third
// of a term, which leaves the agent less than a third to renew in, holds off
// expiry for as long as the gap lasted, keeping a later hold already set. It
// returns the gap it held for, zero if none.
func (p *Plane) Heartbeat(tx store.Tx, now time.Time) (time.Duration, error) {
	gap, err := sinceHeartbeat(tx, now)
	if err != nil {
		return 0, err
	}
	if gap <= p.Config.LeaseTTL/3 {
		gap = 0
	} else if err := holdExpiry(tx, now.Add(gap)); err != nil {
		return 0, err
	}
	return gap, setMetaTime(tx, metaHeartbeat, now)
}

// sinceHeartbeat returns how long ago the last heartbeat was recorded, zero
// if none was.
func sinceHeartbeat(tx store.ReadTx, now time.Time) (time.Duration, error) {
	last, err := metaTime(tx, metaHeartbeat)
	if err != nil || last.IsZero() || !now.After(last) {
		return 0, err
	}
	return now.Sub(last), nil
}

// holdExpiry holds off lease expiry until at least until. It keeps a later
// hold, which another replica's boot or heartbeat may have set.
func holdExpiry(tx store.Tx, until time.Time) error {
	resumes, err := metaTime(tx, metaExpiryResumes)
	if err != nil || !until.After(resumes) {
		return err
	}
	return setMetaTime(tx, metaExpiryResumes, until)
}

// ExpiryResumes reports when lease expiry resumes after a boot or a gap in
// heartbeats.
func ExpiryResumes(tx store.ReadTx) (time.Time, error) { return metaTime(tx, metaExpiryResumes) }

func metaTime(tx store.ReadTx, key string) (time.Time, error) {
	v, ok, err := tx.Meta(key)
	if err != nil || !ok {
		return time.Time{}, err
	}
	return time.Parse(time.RFC3339Nano, v)
}

func setMetaTime(tx store.Tx, key string, t time.Time) error {
	return tx.SetMeta(key, t.UTC().Format(time.RFC3339Nano))
}
