package cp

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"net/netip"
	"slices"
	"strings"
	"testing"
	"time"

	"github.com/danthegoodman1/wirenet/internal/api"
	"github.com/danthegoodman1/wirenet/internal/compile"
	"github.com/danthegoodman1/wirenet/internal/model"
	"github.com/danthegoodman1/wirenet/internal/prng"
	"github.com/danthegoodman1/wirenet/internal/store"
	"github.com/danthegoodman1/wirenet/internal/store/mem"
	"github.com/danthegoodman1/wirenet/internal/store/pgstore/pgtest"
)

var t0 = time.Date(2030, 1, 1, 0, 0, 0, 0, time.UTC)

type fixture struct {
	t      testing.TB
	s      store.Store
	p      *Plane
	now    time.Time
	rng    *prng.Rand
	hosts  map[string]model.HostID
	relays []string
}

func newFixture(t testing.TB, s store.Store) *fixture {
	cfg := DefaultConfig()
	return &fixture{
		t: t, s: s, now: t0, rng: prng.New(1),
		p:     &Plane{Config: cfg, Rand: prng.New(2)},
		hosts: map[string]model.HostID{},
	}
}

// eachStore runs fn over the memory store, and again over Postgres when
// WIRENET_TEST_POSTGRES names a database.
func eachStore(t *testing.T, fn func(t *testing.T, f *fixture)) {
	t.Run("mem", func(t *testing.T) { fn(t, newFixture(t, mem.New())) })
	t.Run("postgres", func(t *testing.T) { fn(t, newFixture(t, pgtest.Open(t))) })
}

func (f *fixture) update(fn func(store.Tx) error) store.Change {
	f.t.Helper()
	ch, err := f.s.Update(context.Background(), fn)
	if err != nil {
		f.t.Fatal(err)
	}
	return ch
}

func (f *fixture) tryUpdate(fn func(store.Tx) error) error {
	_, err := f.s.Update(context.Background(), fn)
	return err
}

func (f *fixture) relay(name string) model.RelayID {
	var id model.RelayID
	octet := byte(1 + len(f.relays))
	f.relays = append(f.relays, name)
	f.update(func(tx store.Tx) error {
		r, _, err := f.p.CreateRelay(tx, f.now, api.CreateRelay{
			Name: name,
			Addresses: []api.RelayAddress{{
				Local:      netip.AddrFrom4([4]byte{10, 0, 0, octet}),
				Advertised: netip.AddrFrom4([4]byte{198, 51, 100, octet}),
			}},
			PortLo: 20000, PortHi: 20099, ProbePort: 19999,
		})
		id = r.ID
		return err
	})
	return id
}

func (f *fixture) network(req api.CreateNetwork) store.Network {
	var n store.Network
	f.update(func(tx store.Tx) error {
		var err error
		n, err = f.p.CreateNetwork(tx, f.now, req)
		return err
	})
	return n
}

func (f *fixture) service(net, name string, ipv4 bool) store.Service {
	var s store.Service
	f.update(func(tx store.Tx) error {
		var err error
		s, err = f.p.CreateService(tx, f.now, Global(), net, api.CreateService{Name: name, IPv4: ipv4})
		return err
	})
	return s
}

func (f *fixture) rule(net, from, to string, proto model.Proto, port uint16) store.Rule {
	var r store.Rule
	f.update(func(tx store.Tx) error {
		var err error
		r, err = f.p.CreateRule(tx, f.now, Global(), net, api.CreateRule{From: from, To: to, Proto: proto, Ports: model.PortRange{Lo: port, Hi: port}})
		return err
	})
	return r
}

func (f *fixture) host(name string) model.HostID {
	if id, ok := f.hosts[name]; ok {
		return id
	}
	f.update(func(tx store.Tx) error {
		h, _, err := f.p.CreateHost(tx, f.now, Global(), api.CreateHost{Name: name})
		f.hosts[name] = h.ID
		return err
	})
	return f.hosts[name]
}

// attach issues an interface and returns it with the private key the agent
// would keep.
func (f *fixture) attach(host, net, svc string) (store.Interface, model.Key) {
	f.t.Helper()
	priv, _ := model.NewPrivateKey(f.rng)
	id, _ := model.NewID(model.InterfacePrefix, f.rng)
	var i store.Interface
	h := f.host(host)
	f.update(func(tx store.Tx) error {
		var err error
		i, _, err = f.p.Attach(tx, f.now, h, api.AttachRequest{
			Interface: model.InterfaceID(id), Network: net, Service: svc,
			PublicKey: priv.Public(), ListenPort: uint16(40000 + f.rng.Below(1000)),
		})
		return err
	})
	return i, priv
}

func (f *fixture) state(host string) api.StateUpdate {
	f.t.Helper()
	var u api.StateUpdate
	if err := f.s.View(context.Background(), func(tx store.ReadTx) error {
		var err error
		u, err = HostState(tx, NoCache{}, f.host(host), 0)
		return err
	}); err != nil {
		f.t.Fatal(err)
	}
	return u
}

func peerIDs(u api.StateUpdate, iface model.InterfaceID) []model.InterfaceID {
	for _, n := range u.Networks {
		if i, ok := n.Interface(iface); ok {
			var out []model.InterfaceID
			for _, p := range i.Peers {
				out = append(out, p.Interface)
			}
			return out
		}
	}
	return nil
}

func sortedIDs(ids ...model.InterfaceID) []model.InterfaceID {
	slices.Sort(ids)
	return ids
}

// TestOverlappingNetworksCompileToExactlyThePermittedPeers is Phase 2's
// gate: two networks on identical prefixes, four interfaces across two
// hosts, and each host's state names exactly the peers policy permits.
func TestOverlappingNetworksCompileToExactlyThePermittedPeers(t *testing.T) {
	eachStore(t, func(t *testing.T, f *fixture) {
		relay := f.relay("r1")
		p6 := netip.MustParsePrefix("fd00:42::/64")
		p4 := netip.MustParsePrefix("10.42.0.0/16")
		f.network(api.CreateNetwork{Name: "shop", Prefix6: p6, Prefix4: p4, Relays: []model.RelayID{relay}})
		f.network(api.CreateNetwork{Name: "bank", Prefix6: p6, Prefix4: p4, Relays: []model.RelayID{relay}})
		for _, net := range []string{"shop", "bank"} {
			f.service(net, "web", true)
			f.service(net, "db", true)
			f.service(net, "batch", true)
		}
		f.rule("shop", "web", "db", model.TCP, 5432)
		f.rule("bank", "batch", "db", model.TCP, 5432)

		shopWeb, _ := f.attach("h1", "shop", "web")
		shopDB, _ := f.attach("h2", "shop", "db")
		bankBatch, _ := f.attach("h1", "bank", "batch")
		bankDB, _ := f.attach("h2", "bank", "db")
		// A shop batch job policy names nowhere: it peers with nothing.
		shopBatch, _ := f.attach("h2", "shop", "batch")

		if shopWeb.Addr6 != bankBatch.Addr6 || shopWeb.Addr4 != bankBatch.Addr4 {
			t.Fatalf("identical prefixes allocated differently: %v %v vs %v %v", shopWeb.Addr6, shopWeb.Addr4, bankBatch.Addr6, bankBatch.Addr4)
		}
		h1, h2 := f.state("h1"), f.state("h2")
		cases := []struct {
			u     api.StateUpdate
			iface store.Interface
			want  []model.InterfaceID
		}{
			{h1, shopWeb, []model.InterfaceID{shopDB.ID}},
			{h1, bankBatch, []model.InterfaceID{bankDB.ID}},
			{h2, shopDB, []model.InterfaceID{shopWeb.ID}},
			{h2, bankDB, []model.InterfaceID{bankBatch.ID}},
			{h2, shopBatch, nil},
		}
		for _, c := range cases {
			if got := peerIDs(c.u, c.iface.ID); !slices.Equal(got, c.want) {
				t.Errorf("%s peers %v, want %v", c.iface.ID, got, c.want)
			}
		}
		// Each peer carries exactly the peer's own address per family, and a
		// relay path with this direction's port.
		for _, n := range h1.Networks {
			for _, i := range n.Interfaces {
				for _, p := range i.Peers {
					if len(p.Allowed) != 2 || p.Allowed[0].Bits() != 128 || p.Allowed[1].Bits() != 32 {
						t.Errorf("%s peer %s allowed %v", i.ID, p.Interface, p.Allowed)
					}
					if len(p.Relays) != 1 || p.Loopback != 0 || p.Keepalive {
						t.Errorf("%s peer %s path %+v", i.ID, p.Interface, p)
					}
				}
			}
		}
	})
}

func TestEdgesCarryOnePortPerDirectionPerRelay(t *testing.T) {
	eachStore(t, func(t *testing.T, f *fixture) {
		r1, r2 := f.relay("r1"), f.relay("r2")
		f.network(api.CreateNetwork{Name: "n", Relays: []model.RelayID{r1, r2}})
		f.service("n", "a", false)
		f.rule("n", "a", "a", model.TCP, 80)
		x, _ := f.attach("h1", "n", "a")
		y, _ := f.attach("h2", "n", "a")
		z, _ := f.attach("h2", "n", "a")
		h1 := f.state("h1")
		xi, _ := h1.Networks[0].Interface(x.ID)
		if len(xi.Peers) != 2 {
			t.Fatalf("x peers %d", len(xi.Peers))
		}
		seen := map[netip.AddrPort]bool{}
		for _, p := range xi.Peers {
			if len(p.Relays) != 2 || p.Relays[0].Relay != r1 || p.Relays[1].Relay != r2 {
				t.Fatalf("relay paths %+v", p.Relays)
			}
			for _, rp := range p.Relays {
				if seen[rp.Send] {
					t.Fatalf("port %v used twice", rp.Send)
				}
				seen[rp.Send] = true
			}
		}
		// y and z share a host, so they peer over loopback with keepalive on
		// exactly one side.
		h2 := f.state("h2")
		yi, _ := h2.Networks[0].Interface(y.ID)
		zi, _ := h2.Networks[0].Interface(z.ID)
		var yz, zy api.Peer
		for _, p := range yi.Peers {
			if p.Interface == z.ID {
				yz = p
			}
		}
		for _, p := range zi.Peers {
			if p.Interface == y.ID {
				zy = p
			}
		}
		if yz.Loopback != z.ListenPort || zy.Loopback != y.ListenPort || len(yz.Relays) != 0 {
			t.Fatalf("loopback paths %+v %+v", yz, zy)
		}
		if yz.Keepalive == zy.Keepalive {
			t.Fatalf("keepalive on both or neither side: %v %v", yz.Keepalive, zy.Keepalive)
		}
		// The relay sees both directions of the x–y edge, each forwarding to
		// the other's port.
		var rs api.RelayState
		f.s.View(context.Background(), func(tx store.ReadTx) error {
			var err error
			rs, err = RelayState(tx, r1)
			return err
		})
		if len(rs.Ports) != 4 {
			t.Fatalf("relay ports %d, want 2 edges × 2 directions", len(rs.Ports))
		}
		for _, p := range rs.Ports {
			var back *api.RelayPort
			for j := range rs.Ports {
				if rs.Ports[j].Local.Port() == p.Peer {
					back = &rs.Ports[j]
				}
			}
			if back == nil || back.Peer != p.Local.Port() {
				t.Fatalf("port %v's peer %d does not point back", p.Local, p.Peer)
			}
		}
	})
}

func TestAnIPv6OnlyServiceDrawsNothingFromTheIPv4Pool(t *testing.T) {
	eachStore(t, func(t *testing.T, f *fixture) {
		n := f.network(api.CreateNetwork{Name: "n", Prefix4: netip.MustParsePrefix("10.9.0.0/30")})
		f.service("n", "six", false)
		for range 5 {
			i, _ := f.attach("h", "n", "six")
			if i.Addr4.IsValid() {
				t.Fatalf("IPv6-only interface got %v", i.Addr4)
			}
		}
		f.s.View(context.Background(), func(tx store.ReadTx) error {
			got, _ := tx.Network(n.ID)
			if got.Next4 != first4 {
				t.Errorf("IPv4 cursor moved to %d", got.Next4)
			}
			return nil
		})
		// A /30 has two usable addresses: the service takes one and one
		// interface the other.
		f.service("n", "four", true)
		f.attach("h", "n", "four")
		err := f.tryUpdate(func(tx store.Tx) error {
			_, _, err := f.p.Attach(tx, f.now, f.host("h"), api.AttachRequest{
				Interface: "if-extra", Network: "n", Service: "four", PublicKey: model.Key{1}, ListenPort: 1,
			})
			return err
		})
		var ae *api.Error
		if !errors.As(err, &ae) || ae.Code != api.CodeExhausted {
			t.Fatalf("attach into a full pool: %v", err)
		}
	})
}

func TestIPv6AddressesAreNeverReused(t *testing.T) {
	eachStore(t, func(t *testing.T, f *fixture) {
		f.network(api.CreateNetwork{Name: "n"})
		f.service("n", "a", false)
		seen := map[netip.Addr]bool{}
		for range 50 {
			i, _ := f.attach("h", "n", "a")
			if seen[i.Addr6] {
				t.Fatalf("%v reused", i.Addr6)
			}
			seen[i.Addr6] = true
			f.update(func(tx store.Tx) error { return f.p.Revoke(tx, f.now, i.ID) })
		}
	})
}

// TestAnIPv4AddressWaitsOutItsQuarantineFromItsHoldersDrain, Phase 2's
// quarantine gate, releases an
// interface on a full prefix and drains it late, as a control plane that
// was down does, and checks its address stays with it until the drain and
// then waits out the quarantine.
func TestAnIPv4AddressWaitsOutItsQuarantineFromItsHoldersDrain(t *testing.T) {
	eachStore(t, func(t *testing.T, f *fixture) {
		f.p.Config.LeaseTTL = time.Hour
		f.network(api.CreateNetwork{Name: "n", Prefix4: netip.MustParsePrefix("10.9.0.0/29")})
		f.service("n", "a", true)
		// A /29 holds six usable addresses: one for the service, five for
		// interfaces.
		var held []store.Interface
		for range 5 {
			i, _ := f.attach("h", "n", "a")
			held = append(held, i)
		}
		gone := held[2]
		f.update(func(tx store.Tx) error { return f.p.Release(tx, f.now, f.host("h"), []model.InterfaceID{gone.ID}) })
		attachAt := func(at time.Time) (store.Interface, error) {
			var i store.Interface
			err := f.tryUpdate(func(tx store.Tx) error {
				var err error
				i, _, err = f.p.Attach(tx, at, f.host("h"), api.AttachRequest{
					Interface: model.InterfaceID(fmt.Sprintf("if-at%d", at.Unix())), Network: "n", Service: "a",
					PublicKey: model.Key{9}, ListenPort: 9,
				})
				return err
			})
			return i, err
		}
		// Peers route a released address until its interface drains, however
		// long past the grace period that takes.
		late := f.now.Add(f.p.Config.DrainGrace + 2*f.p.Config.Quarantine4)
		if _, err := attachAt(late); err == nil {
			t.Fatal("reallocated the address of an interface that has yet to drain")
		}
		f.update(func(tx store.Tx) error {
			_, err := f.p.Sweep(tx, late)
			return err
		})
		if _, err := attachAt(late.Add(f.p.Config.Quarantine4 - time.Second)); err == nil {
			t.Fatal("reallocated an address inside its quarantine")
		}
		i, err := attachAt(late.Add(f.p.Config.Quarantine4 + time.Second))
		if err != nil {
			t.Fatal(err)
		}
		if i.Addr4 != gone.Addr4 {
			t.Fatalf("got %v, want the quarantined %v", i.Addr4, gone.Addr4)
		}
	})
}

// TestRevocationRemovesTheKeyEverywhereWithNoGrace checks that a revoked
// interface leaves every other host's state at once, while a released one
// stays as a draining peer.
func TestRevocationRemovesTheKeyEverywhereWithNoGrace(t *testing.T) {
	eachStore(t, func(t *testing.T, f *fixture) {
		relay := f.relay("r")
		f.network(api.CreateNetwork{Name: "n", Relays: []model.RelayID{relay}})
		f.service("n", "web", false)
		f.service("n", "db", false)
		f.rule("n", "web", "db", model.TCP, 5432)
		db1, _ := f.attach("h1", "n", "db")
		db2, _ := f.attach("h1", "n", "db")
		var webs []store.Interface
		for _, h := range []string{"h2", "h3"} {
			w, _ := f.attach(h, "n", "web")
			webs = append(webs, w)
		}
		f.update(func(tx store.Tx) error { return f.p.Release(tx, f.now, f.host("h1"), []model.InterfaceID{db1.ID}) })
		f.update(func(tx store.Tx) error { return f.p.Revoke(tx, f.now, db2.ID) })
		for i, h := range []string{"h2", "h3"} {
			u := f.state(h)
			wi, _ := u.Networks[0].Interface(webs[i].ID)
			if len(wi.Peers) != 1 || wi.Peers[0].Interface != db1.ID || !wi.Peers[0].Draining {
				t.Fatalf("%s peers %+v; want only the draining db1", h, wi.Peers)
			}
			svc := u.Networks[0].Services[0]
			if len(svc.Backends) != 0 {
				t.Fatalf("%s: service still lists backends %+v", h, svc.Backends)
			}
		}
		// db2's own host learns it was revoked.
		own, _ := f.state("h1").Networks[0].Interface(db2.ID)
		if own.State != api.Revoked || len(own.Peers) != 0 {
			t.Fatalf("revoked interface's own state %+v", own)
		}
		// Once the grace period passes, the released one leaves too.
		f.now = f.now.Add(f.p.Config.DrainGrace + time.Second)
		f.update(func(tx store.Tx) error { _, err := f.p.Sweep(tx, f.now); return err })
		for i, h := range []string{"h2", "h3"} {
			wi, _ := f.state(h).Networks[0].Interface(webs[i].ID)
			if len(wi.Peers) != 0 {
				t.Fatalf("%s still peers with %+v after the grace period", h, wi.Peers)
			}
		}
	})
}

func TestARuleNamingAnEmptyServiceCompilesToNoPeers(t *testing.T) {
	eachStore(t, func(t *testing.T, f *fixture) {
		f.network(api.CreateNetwork{Name: "n"})
		f.service("n", "web", false)
		f.service("n", "db", false)
		f.rule("n", "web", "db", model.TCP, 5432)
		w, _ := f.attach("h", "n", "web")
		n := f.state("h").Networks[0]
		wi, _ := n.Interface(w.ID)
		if len(wi.Peers) != 0 || len(wi.Reach) != 1 {
			t.Fatalf("peers %+v reach %+v", wi.Peers, wi.Reach)
		}
		if len(n.Services) != 1 || len(n.Services[0].Backends) != 0 {
			t.Fatalf("services %+v; want db with no backends", n.Services)
		}
	})
}

func TestMixedFamiliesCompileToIPv6Alone(t *testing.T) {
	eachStore(t, func(t *testing.T, f *fixture) {
		f.network(api.CreateNetwork{Name: "n", Prefix4: netip.MustParsePrefix("10.1.0.0/16")})
		f.service("n", "four", true)
		f.service("n", "six", false)
		f.rule("n", "four", "six", model.TCP, 80)
		a, _ := f.attach("h1", "n", "four")
		b, _ := f.attach("h1", "n", "six")
		n := f.state("h1").Networks[0]
		ai, _ := n.Interface(a.ID)
		bi, _ := n.Interface(b.ID)
		if len(ai.Peers[0].Allowed) != 1 || !ai.Peers[0].Allowed[0].Addr().Is6() {
			t.Fatalf("four's peer allowed %v", ai.Peers[0].Allowed)
		}
		if len(bi.Peers[0].Allowed) != 1 || !bi.Peers[0].Allowed[0].Addr().Is6() {
			t.Fatalf("six's peer allowed %v", bi.Peers[0].Allowed)
		}
		if !a.Addr4.IsValid() || b.Addr4.IsValid() {
			t.Fatalf("addresses %v %v", a.Addr4, b.Addr4)
		}
	})
}

func TestFullyConnectedPolicyPeersEveryPair(t *testing.T) {
	eachStore(t, func(t *testing.T, f *fixture) {
		relay := f.relay("r")
		f.network(api.CreateNetwork{Name: "n", Relays: []model.RelayID{relay}})
		f.service("n", "mesh", false)
		f.rule("n", "mesh", "mesh", model.AnyProto, 0)
		var all []model.InterfaceID
		for i := range 6 {
			x, _ := f.attach(fmt.Sprintf("h%d", i%3), "n", "mesh")
			all = append(all, x.ID)
		}
		slices.Sort(all)
		for h := range 3 {
			for _, n := range f.state(fmt.Sprintf("h%d", h)).Networks {
				for _, i := range n.Interfaces {
					want := slices.DeleteFunc(slices.Clone(all), func(id model.InterfaceID) bool { return id == i.ID })
					if got := peerIDs(api.StateUpdate{Networks: []api.NetworkState{n}}, i.ID); !slices.Equal(got, want) {
						t.Fatalf("%s peers %v, want %v", i.ID, got, want)
					}
				}
			}
		}
		// Six interfaces on three hosts, two per host: 15 pairs, 3 co-located.
		var edges []store.Edge
		f.s.View(context.Background(), func(tx store.ReadTx) error {
			n, _ := tx.NetworkByName("n")
			edges, _ = tx.Edges(n.ID)
			return nil
		})
		if len(edges) != 12 {
			t.Fatalf("%d edges, want 12", len(edges))
		}
	})
}

// TestADisconnectedPairKeepsItsEdgeForTheQuarantine covers a rule that goes
// away and comes back: the pair gets its edge back with the same ports, so
// endpoints peers roamed to stay valid, and the same secrets, so an agent
// that kept the peer through an outage still registers. Only once the
// quarantine passes does the edge go and its ports free up.
func TestADisconnectedPairKeepsItsEdgeForTheQuarantine(t *testing.T) {
	eachStore(t, func(t *testing.T, f *fixture) {
		f.p.Config.LeaseTTL = time.Hour
		relay := f.relay("r")
		f.network(api.CreateNetwork{Name: "n", Relays: []model.RelayID{relay}})
		f.service("n", "a", false)
		f.service("n", "b", false)
		r := f.rule("n", "a", "b", model.TCP, 1)
		f.attach("h1", "n", "a")
		f.attach("h2", "n", "b")
		edges := func() []store.Edge {
			var out []store.Edge
			f.s.View(context.Background(), func(tx store.ReadTx) error {
				n, _ := tx.NetworkByName("n")
				out, _ = tx.Edges(n.ID)
				return nil
			})
			return out
		}
		before := edges()
		f.update(func(tx store.Tx) error { return f.p.DeleteRule(tx, f.now, Global(), "n", r.ID) })
		dormant := edges()
		if len(dormant) != 1 || dormant[0].Dormant.IsZero() {
			t.Fatalf("edges after the rule went: %+v", dormant)
		}
		if dormant[0].SecretAB != before[0].SecretAB || dormant[0].SecretBA != before[0].SecretBA {
			t.Fatal("a dormant edge changed its secrets")
		}
		if peers := peerIDs(f.state("h1"), before[0].A); len(peers) != 0 {
			peers = peerIDs(f.state("h1"), before[0].B)
			if len(peers) != 0 {
				t.Fatalf("a dormant edge still peers %v", peers)
			}
		}
		f.rule("n", "a", "b", model.TCP, 1)
		after := edges()
		if len(after) != 1 || !after[0].Dormant.IsZero() || after[0].Ports[0] != before[0].Ports[0] || after[0].SecretAB != dormant[0].SecretAB {
			t.Fatalf("the restored edge differs: %+v vs %+v", after, before)
		}
		for _, x := range []model.InterfaceID{after[0].A, after[0].B} {
			host := "h1"
			if x == after[0].B {
				host = "h2"
			}
			for _, n := range f.state(host).Networks {
				if i, ok := n.Interface(x); ok && len(i.Peers) != 1 {
					t.Fatalf("%s's peers %+v, want one", x, i.Peers)
				}
			}
		}
		r2 := after[0]
		var rules []store.Rule
		f.s.View(context.Background(), func(tx store.ReadTx) error { rules, _ = tx.Rules(r2.Network); return nil })
		f.update(func(tx store.Tx) error { return f.p.DeleteRule(tx, f.now, Global(), "n", rules[0].ID) })
		f.update(func(tx store.Tx) error {
			_, err := f.p.Sweep(tx, f.now.Add(f.p.Config.PortQuarantine-time.Second))
			return err
		})
		if len(edges()) != 1 {
			t.Fatal("a dormant edge went before the quarantine passed")
		}
		f.update(func(tx store.Tx) error {
			_, err := f.p.Sweep(tx, f.now.Add(f.p.Config.PortQuarantine+time.Second))
			return err
		})
		if len(edges()) != 0 {
			t.Fatal("a dormant edge outlived the quarantine")
		}
		f.s.View(context.Background(), func(tx store.ReadTx) error {
			ports, _ := tx.ReleasedPorts(relay, before[0].Ports[0].Addr, f.now.Add(time.Second), 10)
			if len(ports) != 2 {
				t.Errorf("%d ports free, want 2", len(ports))
			}
			return nil
		})
	})
}

func TestReleasedPortsWaitOutTheirQuarantine(t *testing.T) {
	eachStore(t, func(t *testing.T, f *fixture) {
		relay := f.relay("r") // 100 ports: 50 edges
		f.network(api.CreateNetwork{Name: "n", Relays: []model.RelayID{relay}})
		f.service("n", "a", false)
		f.service("n", "b", false)
		f.rule("n", "a", "b", model.TCP, 1)
		b, _ := f.attach("hb", "n", "b")
		var as []store.Interface
		for i := range 50 {
			a, _ := f.attach(fmt.Sprintf("h%d", i), "n", "a")
			as = append(as, a)
		}
		f.update(func(tx store.Tx) error { return f.p.Revoke(tx, f.now, as[0].ID) })
		err := f.tryUpdate(func(tx store.Tx) error {
			_, _, err := f.p.Attach(tx, f.now.Add(time.Minute), f.host("h0"), api.AttachRequest{
				Interface: "if-late", Network: "n", Service: "a", PublicKey: model.Key{3}, ListenPort: 3,
			})
			return err
		})
		if err == nil {
			t.Fatal("reused a relay port inside its quarantine")
		}
		f.update(func(tx store.Tx) error {
			_, _, err := f.p.Attach(tx, f.now.Add(f.p.Config.PortQuarantine+time.Second), f.host("h0"), api.AttachRequest{
				Interface: "if-later", Network: "n", Service: "a", PublicKey: model.Key{4}, ListenPort: 4,
			})
			return err
		})
		_ = b
	})
}

func TestAttachIsIdempotentForTheSameKey(t *testing.T) {
	eachStore(t, func(t *testing.T, f *fixture) {
		f.network(api.CreateNetwork{Name: "n"})
		f.service("n", "a", false)
		h := f.host("h")
		req := api.AttachRequest{Interface: "if-same", Network: "n", Service: "a", PublicKey: model.Key{7}, ListenPort: 7}
		var first, second store.Interface
		f.update(func(tx store.Tx) error { var err error; first, _, err = f.p.Attach(tx, f.now, h, req); return err })
		f.update(func(tx store.Tx) error { var err error; second, _, err = f.p.Attach(tx, f.now, h, req); return err })
		if first.Addr6 != second.Addr6 {
			t.Fatalf("retried attach got a second address %v, then %v", first.Addr6, second.Addr6)
		}
		req.PublicKey = model.Key{8}
		if err := f.tryUpdate(func(tx store.Tx) error { _, _, err := f.p.Attach(tx, f.now, h, req); return err }); err == nil {
			t.Fatal("a second key took over an interface")
		}
	})
}

// TestTheControlPlaneNeverStoresAPrivateKey attaches interfaces and checks
// that no record holds a private key the agents minted.
func TestTheControlPlaneNeverStoresAPrivateKey(t *testing.T) {
	eachStore(t, func(t *testing.T, f *fixture) {
		f.network(api.CreateNetwork{Name: "n"})
		f.service("n", "a", false)
		f.rule("n", "a", "a", model.TCP, 1)
		var privs []model.Key
		for range 4 {
			_, priv := f.attach("h", "n", "a")
			privs = append(privs, priv)
		}
		var dump strings.Builder
		f.s.View(context.Background(), func(tx store.ReadTx) error {
			nets, _ := tx.Networks()
			for _, n := range nets {
				for _, v := range []any{
					n, must(tx.Services(n.ID)), must(tx.Interfaces(n.ID)), must(tx.Rules(n.ID)), must(tx.Edges(n.ID)),
				} {
					b, _ := json.Marshal(v)
					dump.Write(b)
				}
			}
			return nil
		})
		u := f.state("h")
		b, _ := json.Marshal(u)
		dump.Write(b)
		for _, k := range privs {
			if strings.Contains(dump.String(), k.String()) {
				t.Fatal("a private key reached the control plane")
			}
			if !strings.Contains(dump.String(), k.Public().String()) {
				t.Fatal("dump lacks a public key, so the check proves nothing")
			}
		}
	})
}

func must[T any](v T, err error) T {
	if err != nil {
		panic(err)
	}
	return v
}

func TestExpiryWaitsOutTheControlPlanesDowntime(t *testing.T) {
	eachStore(t, func(t *testing.T, f *fixture) {
		f.network(api.CreateNetwork{Name: "n"})
		f.service("n", "a", false)
		f.update(func(tx store.Tx) error { _, err := f.p.Heartbeat(tx, f.now); return err })
		i, _ := f.attach("h", "n", "a")
		// The control plane goes down for ten minutes, far past the lease.
		down := 10 * time.Minute
		f.now = f.now.Add(down)
		f.update(func(tx store.Tx) error { _, err := f.p.Boot(tx, f.now); return err })
		f.update(func(tx store.Tx) error { _, err := f.p.Sweep(tx, f.now.Add(time.Minute)); return err })
		f.s.View(context.Background(), func(tx store.ReadTx) error {
			got, _ := tx.Interface(i.ID)
			if got.State != api.Live {
				t.Errorf("revoked %s a minute after recovery", i.ID)
			}
			return nil
		})
		// An agent that never renews loses its lease once the wait ends.
		f.update(func(tx store.Tx) error { _, err := f.p.Sweep(tx, f.now.Add(down+time.Second)); return err })
		f.s.View(context.Background(), func(tx store.ReadTx) error {
			got, _ := tx.Interface(i.ID)
			if got.State != api.Revoked {
				t.Errorf("state %s after the wait", got.State)
			}
			return nil
		})
	})
}

func (f *fixture) heartbeat() time.Duration {
	f.t.Helper()
	var gap time.Duration
	f.update(func(tx store.Tx) error {
		var err error
		gap, err = f.p.Heartbeat(tx, f.now)
		return err
	})
	return gap
}

func (f *fixture) sweep(at time.Time) {
	f.t.Helper()
	f.update(func(tx store.Tx) error { _, err := f.p.Sweep(tx, at); return err })
}

// TestExpiryHoldsThroughAStoreOutage keeps the control plane up while its
// store answers nothing. A healthy lease has at least two thirds of a term
// left, so the outages here end after the lease does: one shorter than a
// term, and one longer.
func TestExpiryHoldsThroughAStoreOutage(t *testing.T) {
	for _, gap := range []time.Duration{26 * time.Second, DefaultConfig().LeaseTTL + time.Minute} {
		t.Run(gap.String(), func(t *testing.T) {
			eachStore(t, func(t *testing.T, f *fixture) {
				f.network(api.CreateNetwork{Name: "n"})
				f.service("n", "a", false)
				f.update(func(tx store.Tx) error { _, err := f.p.Boot(tx, f.now); return err })
				i, _ := f.attach("h", "n", "a")
				beat := func() {
					f.now = f.now.Add(5 * time.Second)
					if held := f.heartbeat(); held != 0 {
						t.Fatalf("a heartbeat 5s after the last held expiry for %v", held)
					}
				}
				beat()
				beat()
				f.update(func(tx store.Tx) error {
					_, err := f.p.Renew(tx, f.now, f.host("h"), []model.InterfaceID{i.ID})
					return err
				})
				beat()
				// The lease ends 25s after the last heartbeat, and the store
				// answers again later than that.
				f.now = f.now.Add(gap)
				if held := f.heartbeat(); held != gap {
					t.Fatalf("the heartbeat after the outage held expiry for %v, want %v", held, gap)
				}
				f.sweep(f.now)
				if st := f.interfaceState(i.ID); st != api.Live {
					t.Fatalf("the first sweep after the outage left the lease %s", st)
				}
				// An agent that never renews loses its lease once the hold ends.
				f.sweep(f.now.Add(gap + time.Second))
				if st := f.interfaceState(i.ID); st != api.Revoked {
					t.Fatalf("the lease is %s after the hold", st)
				}
			})
		})
	}
}

// TestASecondBootKeepsTheLongerHold boots twice after a long outage, as a
// second replica or a crash loop would: the second boot keeps the first
// boot's hold.
func TestASecondBootKeepsTheLongerHold(t *testing.T) {
	eachStore(t, func(t *testing.T, f *fixture) {
		f.network(api.CreateNetwork{Name: "n"})
		f.service("n", "a", false)
		f.heartbeat()
		i, _ := f.attach("h", "n", "a")
		f.now = f.now.Add(10 * time.Minute)
		f.update(func(tx store.Tx) error { _, err := f.p.Boot(tx, f.now); return err })
		f.now = f.now.Add(5 * time.Second)
		f.update(func(tx store.Tx) error { _, err := f.p.Boot(tx, f.now); return err })
		f.sweep(f.now.Add(time.Minute))
		if st := f.interfaceState(i.ID); st != api.Live {
			t.Fatalf("a minute after the second boot the lease is %s", st)
		}
	})
}

// TestDeletingAHostRevokesItsInterfaces deletes a host running a workload
// and a gateway with a development machine behind it: its peers drop both
// at once, the machine goes with its gateway, the host's token finds
// nothing, and later sweeps run clean.
func TestDeletingAHostRevokesItsInterfaces(t *testing.T) {
	eachStore(t, func(t *testing.T, f *fixture) {
		gw, db, _ := shopWithDevices(f)
		f.service("shop", "web", true)
		f.rule("shop", "web", "db", model.TCP, 5432)
		web, _ := f.attach("edge", "shop", "web")
		laptop, err := f.device("shop", "dev", gw.ID, 24*time.Hour)
		if err != nil {
			t.Fatal(err)
		}
		if got := peerIDs(f.state("h2"), db.ID); !slices.Equal(got, sortedIDs(gw.ID, web.ID)) {
			t.Fatalf("db's peers before the delete: %v", got)
		}
		var h store.Host
		f.update(func(tx store.Tx) error {
			var err error
			h, err = f.p.DeleteHost(tx, f.now, Global(), "edge")
			return err
		})
		if got := peerIDs(f.state("h2"), db.ID); len(got) != 0 {
			t.Fatalf("db still peers with %v", got)
		}
		for _, id := range []model.InterfaceID{gw.ID, web.ID, laptop.ID} {
			if st := f.interfaceState(id); st != "" {
				t.Fatalf("%s is still on record, %s", id, st)
			}
		}
		if err := f.s.View(t.Context(), func(tx store.ReadTx) error {
			if edges := must(tx.RelayEdges(must(tx.RelayByName("r")).ID)); len(edges) != 0 {
				t.Errorf("the relay still serves %d edges", len(edges))
			}
			_, err := tx.HostByToken(h.TokenHash)
			return err
		}); !errors.Is(err, store.ErrNotFound) {
			t.Fatalf("the deleted host's token: %v", err)
		}
		f.now = f.now.Add(f.p.Config.Retention + f.p.Config.PortQuarantine)
		f.sweep(f.now)
		err = f.tryUpdate(func(tx store.Tx) error { _, err := f.p.DeleteHost(tx, f.now, Global(), string(h.ID)); return err })
		if code(err) != api.CodeNotFound {
			t.Fatalf("deleting the host again: %v", err)
		}
	})
}

func code(err error) string {
	var ae *api.Error
	if errors.As(err, &ae) {
		return ae.Code
	}
	return ""
}

// TestARelayIsDeletedOnlyOnceNoNetworkNamesIt refuses to delete a relay a
// network names, and deletes it once the network is gone.
func TestARelayIsDeletedOnlyOnceNoNetworkNamesIt(t *testing.T) {
	eachStore(t, func(t *testing.T, f *fixture) {
		relay := f.relay("r")
		f.network(api.CreateNetwork{Name: "n", Relays: []model.RelayID{relay}})
		del := func() error {
			return f.tryUpdate(func(tx store.Tx) error { _, err := f.p.DeleteRelay(tx, "r"); return err })
		}
		if err := del(); code(err) != api.CodeConflict {
			t.Fatalf("deleting a relay a network names: %v", err)
		}
		f.update(func(tx store.Tx) error { return f.p.DeleteNetwork(tx, "n") })
		if err := del(); err != nil {
			t.Fatal(err)
		}
		if err := f.s.View(t.Context(), func(tx store.ReadTx) error { _, err := tx.Relay(relay); return err }); !errors.Is(err, store.ErrNotFound) {
			t.Fatalf("the deleted relay: %v", err)
		}
	})
}

// TestNoNewEdgeTowardADrainingInterface releases a backend, then attaches a
// client policy connects to it: the client gets no edge and no peer for the
// draining backend, which keeps the edge it already had.
func TestNoNewEdgeTowardADrainingInterface(t *testing.T) {
	eachStore(t, func(t *testing.T, f *fixture) {
		relay := f.relay("r")
		f.network(api.CreateNetwork{Name: "n", Relays: []model.RelayID{relay}})
		f.service("n", "a", false)
		f.service("n", "b", false)
		f.rule("n", "a", "b", model.TCP, 80)
		b, _ := f.attach("hb", "n", "b")
		a1, _ := f.attach("h1", "n", "a")
		f.update(func(tx store.Tx) error { return f.p.Release(tx, f.now, f.host("hb"), []model.InterfaceID{b.ID}) })
		a2, _ := f.attach("h2", "n", "a")
		var pairs [][2]model.InterfaceID
		f.s.View(t.Context(), func(tx store.ReadTx) error {
			n, err := ResolveNetwork(tx, "n")
			if err != nil {
				return err
			}
			for _, e := range must(tx.Edges(n.ID)) {
				pairs = append(pairs, [2]model.InterfaceID{e.A, e.B})
			}
			return nil
		})
		x, y := compile.Pair(a1.ID, b.ID)
		if len(pairs) != 1 || pairs[0] != [2]model.InterfaceID{x, y} {
			t.Fatalf("edges %v, want only the draining backend's own", pairs)
		}
		if got := peerIDs(f.state("h2"), a2.ID); len(got) != 0 {
			t.Fatalf("the new client peers with %v", got)
		}
	})
}

// TestDeletingANetworkMovesItsHostsOn deletes a network whose host still
// sees its drained interface: the host's generation moves, so its poll
// answers, and the answer drops the network.
func TestDeletingANetworkMovesItsHostsOn(t *testing.T) {
	eachStore(t, func(t *testing.T, f *fixture) {
		f.network(api.CreateNetwork{Name: "n"})
		f.service("n", "a", false)
		i, _ := f.attach("h", "n", "a")
		f.update(func(tx store.Tx) error { return f.p.Release(tx, f.now, f.host("h"), []model.InterfaceID{i.ID}) })
		f.now = f.now.Add(f.p.Config.DrainGrace + time.Second)
		f.sweep(f.now)
		held := api.NewHostState()
		if err := held.Apply(f.state("h")); err != nil || len(held.Networks) != 1 {
			t.Fatalf("before the delete the host holds %d networks: %v", len(held.Networks), err)
		}
		f.update(func(tx store.Tx) error { return f.p.DeleteNetwork(tx, "n") })
		var u api.StateUpdate
		if err := f.s.View(t.Context(), func(tx store.ReadTx) error {
			var err error
			u, err = HostState(tx, NoCache{}, f.host("h"), held.Generation)
			return err
		}); err != nil {
			t.Fatal(err)
		}
		if u.Generation <= held.Generation {
			t.Fatalf("the host's generation stayed at %d", u.Generation)
		}
		if err := held.Apply(u); err != nil || len(held.Networks) != 0 {
			t.Fatalf("after the delete the host holds %d networks: %v", len(held.Networks), err)
		}
	})
}

var errBroken = errors.New("store broken")

// brokenTx fails one read, as a store that loses its connection would.
type brokenTx struct {
	store.Tx
	read string
}

func (t brokenTx) Rule(id model.RuleID) (store.Rule, error) {
	if t.read == "Rule" {
		return store.Rule{}, errBroken
	}
	return t.Tx.Rule(id)
}

func (t brokenTx) Interface(id model.InterfaceID) (store.Interface, error) {
	if t.read == "Interface" {
		return store.Interface{}, errBroken
	}
	return t.Tx.Interface(id)
}

func (t brokenTx) Host(id model.HostID) (store.Host, error) {
	if t.read == "Host" {
		return store.Host{}, errBroken
	}
	return t.Tx.Host(id)
}

// TestStoreErrorsComeBackAsErrors fails the read each call depends on and
// checks the call returns the store's error rather than a verdict about
// the records.
func TestStoreErrorsComeBackAsErrors(t *testing.T) {
	eachStore(t, func(t *testing.T, f *fixture) {
		gw, _, _ := shopWithDevices(f)
		rule := f.rule("shop", "edge", "db", model.TCP, 1)
		laptop, err := f.device("shop", "dev", gw.ID, time.Hour)
		if err != nil {
			t.Fatal(err)
		}
		calls := []struct {
			name string
			call func(tx store.Tx) error
		}{
			{"DeleteRule", func(tx store.Tx) error {
				return f.p.DeleteRule(brokenTx{tx, "Rule"}, f.now, Global(), "shop", rule.ID)
			}},
			{"RevokeIn", func(tx store.Tx) error {
				var shop store.Network
				shop, err := tx.NetworkByName("shop")
				if err != nil {
					return err
				}
				return f.p.RevokeIn(brokenTx{tx, "Interface"}, f.now, store.Scope{Networks: []model.NetworkID{shop.ID}}, laptop.ID)
			}},
			{"DeviceConfig", func(tx store.Tx) error {
				_, err := DeviceConfig(brokenTx{tx, "Interface"}, laptop.ID)
				return err
			}},
			{"CreateDevice", func(tx store.Tx) error {
				_, err := f.p.CreateDevice(brokenTx{tx, "Host"}, f.now, Global(), "shop", api.CreateDevice{
					Service: "dev", Gateway: gw.ID, PublicKey: model.Key{9}, TTL: time.Hour,
				})
				return err
			}},
		}
		for _, c := range calls {
			if err := f.tryUpdate(c.call); !errors.Is(err, errBroken) {
				t.Errorf("%s over a broken store: %v", c.name, err)
			}
		}
	})
}

func TestConfigNeedsAPortQuarantine(t *testing.T) {
	c := DefaultConfig()
	c.PortQuarantine = 0
	if c.Validate() == nil {
		t.Fatal("a zero port quarantine validated")
	}
}

func TestStateUpdatesCarryOnlyChangedNetworks(t *testing.T) {
	eachStore(t, func(t *testing.T, f *fixture) {
		f.network(api.CreateNetwork{Name: "a"})
		f.network(api.CreateNetwork{Name: "b"})
		f.service("a", "s", false)
		f.service("b", "s", false)
		f.attach("h", "a", "s")
		f.attach("h", "b", "s")
		h := api.NewHostState()
		full := f.state("h")
		if err := h.Apply(full); err != nil {
			t.Fatal(err)
		}
		f.attach("h", "b", "s")
		var delta api.StateUpdate
		f.s.View(context.Background(), func(tx store.ReadTx) error {
			var err error
			delta, err = HostState(tx, NoCache{}, f.host("h"), h.Generation)
			return err
		})
		if len(delta.Networks) != 1 || delta.Networks[0].Name != "b" || len(delta.Present) != 2 {
			t.Fatalf("delta carries %d networks, presents %d", len(delta.Networks), len(delta.Present))
		}
		if err := h.Apply(delta); err != nil {
			t.Fatal(err)
		}
		again := api.NewHostState()
		again.Apply(f.state("h"))
		a, _ := json.Marshal(h.Networks)
		b, _ := json.Marshal(again.Networks)
		if string(a) != string(b) {
			t.Fatal("a full state and a delta applied to the previous state differ")
		}
	})
}
