//wirenet:deterministic

package cp

import (
	"slices"
	"time"

	"github.com/danthegoodman1/wirenet/internal/api"
	"github.com/danthegoodman1/wirenet/internal/compile"
	"github.com/danthegoodman1/wirenet/internal/model"
	"github.com/danthegoodman1/wirenet/internal/store"
)

// scope limits an edge reconciliation to the pairs a change can affect.
type scope struct {
	iface    model.InterfaceID
	service  model.ServiceID
	services [2]model.ServiceID
	all      bool
}

func interfaceScope(id model.InterfaceID) scope { return scope{iface: id} }

func servicesScope(a, b model.ServiceID) scope { return scope{services: [2]model.ServiceID{a, b}} }

// serviceScope covers every pair with an interface of s.
func serviceScope(s model.ServiceID) scope { return scope{service: s} }

// ruleScope covers the pairs a rule between services names.
func ruleScope(r store.Rule) scope {
	switch {
	case r.From == model.AnyService && r.To == model.AnyService:
		return networkScope()
	case r.From == model.AnyService:
		return serviceScope(r.To)
	case r.To == model.AnyService:
		return serviceScope(r.From)
	}
	return servicesScope(r.From, r.To)
}

// edgeScope covers the edges an interface's end changes. A development
// machine's edges are its gateway's.
func edgeScope(i store.Interface) scope {
	if i.Kind == api.Device {
		return interfaceScope(i.Gateway)
	}
	return interfaceScope(i.ID)
}

// networkScope covers every pair, for a change whose reach a gateway's
// development machines widen.
func networkScope() scope { return scope{all: true} }

func (s scope) covers(x, y store.Interface) bool {
	if s.all {
		return true
	}
	if s.iface != "" {
		return x.ID == s.iface || y.ID == s.iface
	}
	if s.service != "" {
		return x.Service == s.service || y.Service == s.service
	}
	a, b := s.services[0], s.services[1]
	return x.Service == a && y.Service == b || x.Service == b && y.Service == a
}

// pairs lists the pairs of connected interfaces within scope, each ordered as
// an edge stores it. connected is sorted by identifier.
func (s scope) pairs(connected []store.Interface) [][2]store.Interface {
	var out [][2]store.Interface
	if s.all {
		for i, x := range connected {
			for _, y := range connected[i+1:] {
				out = append(out, [2]store.Interface{x, y})
			}
		}
		return out
	}
	if s.iface != "" {
		i := slices.IndexFunc(connected, func(x store.Interface) bool { return x.ID == s.iface })
		if i < 0 {
			return nil
		}
		x := connected[i]
		for _, y := range connected {
			switch {
			case y.ID < x.ID:
				out = append(out, [2]store.Interface{y, x})
			case y.ID > x.ID:
				out = append(out, [2]store.Interface{x, y})
			}
		}
		return out
	}
	if s.service != "" {
		for i, x := range connected {
			if x.Service != s.service {
				continue
			}
			for j, y := range connected {
				switch {
				case j == i || j < i && y.Service == s.service:
					// A pair within the service comes once, from its first.
				case j < i:
					out = append(out, [2]store.Interface{y, x})
				default:
					out = append(out, [2]store.Interface{x, y})
				}
			}
		}
		return out
	}
	for i, x := range connected {
		if x.Service != s.services[0] && x.Service != s.services[1] {
			continue
		}
		for _, y := range connected[i+1:] {
			if s.covers(x, y) {
				out = append(out, [2]store.Interface{x, y})
			}
		}
	}
	return out
}

// holdings is what a network holds once reconcileEdges has run, counted
// from the rows it read: live interfaces, and edges before and after it.
type holdings struct {
	live                    int
	edgesBefore, edgesAfter int
}

// reconcileEdges makes the network's edges within scope match what policy
// and placement want: an edge for every policy-connected pair of connected
// interfaces on different hosts, each with ports on every relay of the set.
// It returns what the network then holds, so a change can check its quota
// without reading again.
func (p *Plane) reconcileEdges(tx store.Tx, now time.Time, n *store.Network, sc scope) (holdings, error) {
	ifaces, err := tx.Interfaces(n.ID)
	if err != nil {
		return holdings{}, err
	}
	rules, err := tx.Rules(n.ID)
	if err != nil {
		return holdings{}, err
	}
	svcs, err := tx.Services(n.ID)
	if err != nil {
		return holdings{}, err
	}
	links := compile.NewLinks(compile.NewAdjacency(compile.Resolve(svcs, rules)), ifaces)
	if links.HasDevices() && sc.iface == "" {
		// A rule naming a development machine's service changes which
		// interfaces its gateway peers with.
		sc = networkScope()
	}
	// A development machine reaches the network through its gateway, so
	// edges join the interfaces agents run.
	connected := slices.DeleteFunc(slices.Clone(ifaces), func(i store.Interface) bool {
		return !compile.Connected(i) || !compile.Built(i)
	})
	var wanted [][2]model.InterfaceID
	want := map[[2]model.InterfaceID]bool{}
	for _, pair := range sc.pairs(connected) {
		x, y := pair[0], pair[1]
		if x.Host != y.Host && links.Connects(x, y) {
			key := [2]model.InterfaceID{x.ID, y.ID}
			want[key] = true
			wanted = append(wanted, key)
		}
	}
	byID := map[model.InterfaceID]store.Interface{}
	for _, i := range ifaces {
		byID[i.ID] = i
	}
	edges, err := tx.Edges(n.ID)
	if err != nil {
		return holdings{}, err
	}
	h := holdings{live: live(ifaces), edgesBefore: len(edges), edgesAfter: len(edges)}
	var touched []model.RelayID
	have := map[[2]model.InterfaceID]bool{}
	for _, e := range edges {
		x, okx := byID[e.A]
		y, oky := byID[e.B]
		attached := okx && oky && compile.Connected(x) && compile.Connected(y)
		if attached && !sc.covers(x, y) {
			continue
		}
		key := [2]model.InterfaceID{e.A, e.B}
		switch {
		case want[key]:
			have[key] = true
			if !e.Dormant.IsZero() {
				e.Dormant = time.Time{}
				if err := tx.PutEdge(e); err != nil {
					return holdings{}, err
				}
			}
		case attached:
			// Policy no longer connects a pair that is still attached: keep
			// the edge, dormant, in case it reconnects. Its relays hold
			// what they did; each agent withdraws its direction as it
			// removes the peer.
			if e.Dormant.IsZero() {
				e.Dormant = now
				if err := tx.PutEdge(e); err != nil {
					return holdings{}, err
				}
			}
		default:
			if err := releasePorts(tx, e, now); err != nil {
				return holdings{}, err
			}
			if err := tx.DeleteEdge(n.ID, e.A, e.B); err != nil {
				return holdings{}, err
			}
			h.edgesAfter--
			touched = append(touched, relayIDs(e)...)
		}
	}
	relays := make([]store.Relay, 0, len(n.Relays))
	for _, id := range n.Relays {
		r, err := tx.Relay(id)
		if err != nil {
			return holdings{}, notFound(err, "relay "+string(id))
		}
		relays = append(relays, r)
	}
	for _, key := range wanted {
		// A draining interface keeps its edges until it drains and gains
		// none: its own host has stopped configuring it, so a new edge
		// would only spend relay ports.
		if have[key] || byID[key[0]].State != api.Live || byID[key[1]].State != api.Live {
			continue
		}
		e := store.Edge{Network: n.ID, A: key[0], B: key[1], Created: now}
		if e.SecretAB, err = model.NewSecret(p.Rand); err != nil {
			return holdings{}, err
		}
		if e.SecretBA, err = model.NewSecret(p.Rand); err != nil {
			return holdings{}, err
		}
		for _, r := range relays {
			ports, err := p.allocPorts(tx, r, now)
			if err != nil {
				return holdings{}, err
			}
			e.Ports = append(e.Ports, ports)
		}
		if err := tx.PutEdge(e); err != nil {
			return holdings{}, err
		}
		h.edgesAfter++
		touched = append(touched, relayIDs(e)...)
	}
	return h, bumpRelays(tx, touched)
}

// expireDormant deletes edges dormant for a port quarantine. Their ports
// have had no sender since they went dormant, so they are free at once.
func (p *Plane) expireDormant(tx store.Tx, now time.Time, limit int) (int, error) {
	old, err := tx.DormantEdges(now.Add(-p.Config.PortQuarantine), limit)
	if err != nil {
		return 0, err
	}
	var touched []model.RelayID
	for _, e := range old {
		if err := releasePorts(tx, e, e.Dormant); err != nil {
			return 0, err
		}
		if err := tx.DeleteEdge(e.Network, e.A, e.B); err != nil {
			return 0, err
		}
		touched = append(touched, relayIDs(e)...)
	}
	return len(old), bumpRelays(tx, touched)
}

// bumpRelays gives every touched relay this transaction's revision, so its
// long poll wakes for the new port table.
func bumpRelays(tx store.Tx, ids []model.RelayID) error {
	if len(ids) == 0 {
		return nil
	}
	slices.Sort(ids)
	ids = slices.Compact(ids)
	rev, err := tx.Bump()
	if err != nil {
		return err
	}
	for _, id := range ids {
		r, err := tx.Relay(id)
		if err != nil {
			return err
		}
		r.Revision = rev
		if err := tx.PutRelay(r); err != nil {
			return err
		}
	}
	tx.Touch(store.Change{Relays: ids})
	return nil
}
