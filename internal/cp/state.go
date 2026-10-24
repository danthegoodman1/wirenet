//wirenet:deterministic

package cp

import (
	"fmt"
	"slices"

	"github.com/danthegoodman1/wirenet/internal/api"
	"github.com/danthegoodman1/wirenet/internal/compile"
	"github.com/danthegoodman1/wirenet/internal/model"
	"github.com/danthegoodman1/wirenet/internal/store"
)

// Compiled is one network's state for every host, at one revision.
type Compiled map[model.HostID]api.NetworkState

// Cache keeps compiled networks by revision. A network's revision changes
// with every record its compilation reads, so an entry never goes stale.
type Cache interface {
	Get(net model.NetworkID, revision uint64) (Compiled, bool)
	Put(net model.NetworkID, revision uint64, c Compiled)
}

// NoCache compiles every time.
type NoCache struct{}

func (NoCache) Get(model.NetworkID, uint64) (Compiled, bool) { return nil, false }
func (NoCache) Put(model.NetworkID, uint64, Compiled)        {}

// ReadSnapshot reads everything a network's compilation depends on.
func ReadSnapshot(tx store.ReadTx, n store.Network) (compile.Snapshot, error) {
	s := compile.Snapshot{Network: n}
	var err error
	if s.Services, err = tx.Services(n.ID); err != nil {
		return s, err
	}
	if s.Interfaces, err = tx.Interfaces(n.ID); err != nil {
		return s, err
	}
	if s.Rules, err = tx.Rules(n.ID); err != nil {
		return s, err
	}
	if s.Edges, err = tx.Edges(n.ID); err != nil {
		return s, err
	}
	for _, id := range n.Relays {
		r, err := tx.Relay(id)
		if err != nil {
			return s, notFound(err, "relay "+string(id))
		}
		s.Relays = append(s.Relays, r)
	}
	return s, nil
}

// CompileNetwork returns a network's compiled state, from the cache when it
// holds the network's revision.
func CompileNetwork(tx store.ReadTx, cache Cache, n store.Network) (Compiled, error) {
	if c, ok := cache.Get(n.ID, n.Revision); ok {
		return c, nil
	}
	snap, err := ReadSnapshot(tx, n)
	if err != nil {
		return nil, err
	}
	c := Compiled(compile.Network(snap))
	cache.Put(n.ID, n.Revision, c)
	return c, nil
}

// HostGeneration returns a host's generation: the newest revision among the
// host's own record and the networks its scope admits where it builds
// interfaces. Every change to what the host should run raises one of them.
func HostGeneration(tx store.ReadTx, host model.HostID) (uint64, []store.Network, error) {
	h, err := tx.Host(host)
	if err != nil {
		return 0, nil, notFound(err, "host "+string(host))
	}
	ifaces, err := tx.HostInterfaces(host)
	if err != nil {
		return 0, nil, err
	}
	var ids []model.NetworkID
	for _, i := range ifaces {
		// A network the host's scope lost keeps its revoked interfaces'
		// records until they expire, and polling it would show the host
		// every service address the network gains meanwhile. Its agent
		// fences a network gone from its poll as it fences a revocation.
		if compile.Built(i) && h.Scope.Admits(i.Network) {
			ids = append(ids, i.Network)
		}
	}
	slices.Sort(ids)
	ids = slices.Compact(ids)
	gen := h.Revision
	nets := make([]store.Network, 0, len(ids))
	for _, id := range ids {
		n, err := tx.Network(id)
		if err != nil {
			return 0, nil, err
		}
		gen = max(gen, n.Revision)
		nets = append(nets, n)
	}
	return gen, nets, nil
}

// HostState answers a host's poll from generation since: every network whose
// revision passed it, and the list of every network the host holds.
func HostState(tx store.ReadTx, cache Cache, host model.HostID, since uint64) (api.StateUpdate, error) {
	gen, nets, err := HostGeneration(tx, host)
	if err != nil {
		return api.StateUpdate{}, err
	}
	u := api.StateUpdate{Host: host, Generation: gen, Present: []api.NetworkRef{}}
	for _, n := range nets {
		u.Present = append(u.Present, api.NetworkRef{Network: n.ID, Revision: n.Revision})
		if n.Revision <= since {
			continue
		}
		c, err := CompileNetwork(tx, cache, n)
		if err != nil {
			return api.StateUpdate{}, err
		}
		ns, ok := c[host]
		if !ok {
			return api.StateUpdate{}, fmt.Errorf("network %s compiled nothing for host %s", n.ID, host)
		}
		u.Networks = append(u.Networks, ns)
	}
	return u, nil
}

// AttachState answers an attach with its interface's network as its host
// builds it. It reads after the attach commits, so it carries the revision
// the attach made. A rescope or revocation since may have ended the
// interface, and only a live interface's network lies within its host's
// scope, so an ended one answers with nothing of its network.
func AttachState(tx store.ReadTx, cache Cache, id model.InterfaceID, host model.HostID) (api.NetworkState, error) {
	i, err := tx.Interface(id)
	if err == nil && i.Host != host {
		// The interface expired and another host attached under its
		// identifier.
		err = store.ErrNotFound
	}
	if err != nil {
		return api.NetworkState{}, notFound(err, "interface "+string(id))
	}
	if i.State != api.Live {
		return api.NetworkState{}, apiErr(api.CodeConflict, "interface %s was %s before its attach answered", id, i.State)
	}
	n, err := tx.Network(i.Network)
	if err != nil {
		return api.NetworkState{}, notFound(err, "network "+string(i.Network))
	}
	c, err := CompileNetwork(tx, cache, n)
	if err != nil {
		return api.NetworkState{}, err
	}
	ns, ok := c[host]
	if !ok {
		return api.NetworkState{}, apiErr(api.CodeNotFound, "host %s builds nothing in network %s", host, n.Name)
	}
	return ns, nil
}

// RelayState returns a relay's port table.
func RelayState(tx store.ReadTx, relay model.RelayID) (api.RelayState, error) {
	r, err := tx.Relay(relay)
	if err != nil {
		return api.RelayState{}, notFound(err, "relay "+string(relay))
	}
	edges, err := tx.RelayEdges(relay)
	if err != nil {
		return api.RelayState{}, err
	}
	return compile.Relay(r, edges, r.Revision), nil
}

// LRU is a deterministic cache holding a bounded number of compiled
// networks, evicting the least recently used.
type LRU struct {
	cap     int
	entries map[lruKey]Compiled
	order   []lruKey
}

type lruKey struct {
	net model.NetworkID
	rev uint64
}

// NewLRU returns a cache holding up to capacity networks.
func NewLRU(capacity int) *LRU {
	return &LRU{cap: capacity, entries: map[lruKey]Compiled{}}
}

func (l *LRU) Get(net model.NetworkID, rev uint64) (Compiled, bool) {
	k := lruKey{net, rev}
	c, ok := l.entries[k]
	if ok {
		l.touch(k)
	}
	return c, ok
}

func (l *LRU) Put(net model.NetworkID, rev uint64, c Compiled) {
	k := lruKey{net, rev}
	if _, ok := l.entries[k]; !ok && len(l.entries) >= l.cap && len(l.order) > 0 {
		delete(l.entries, l.order[0])
		l.order = l.order[1:]
	}
	l.entries[k] = c
	l.touch(k)
}

func (l *LRU) touch(k lruKey) {
	if i := slices.Index(l.order, k); i >= 0 {
		l.order = slices.Delete(l.order, i, i+1)
	}
	l.order = append(l.order, k)
}
