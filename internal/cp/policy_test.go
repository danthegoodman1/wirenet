package cp

import (
	"cmp"
	"context"
	"errors"
	"fmt"
	"net/netip"
	"slices"
	"testing"

	"github.com/danthegoodman1/wirenet/internal/api"
	"github.com/danthegoodman1/wirenet/internal/compile"
	"github.com/danthegoodman1/wirenet/internal/model"
	"github.com/danthegoodman1/wirenet/internal/prng"
	"github.com/danthegoodman1/wirenet/internal/store"
)

func (f *fixture) createRule(net string, req api.CreateRule) (store.Rule, error) {
	var r store.Rule
	err := f.tryUpdate(func(tx store.Tx) error {
		var err error
		r, err = f.p.CreateRule(tx, f.now, Global(), net, req)
		return err
	})
	return r, err
}

func (f *fixture) edgePairs(net string) [][2]model.InterfaceID {
	f.t.Helper()
	var out [][2]model.InterfaceID
	if err := f.s.View(context.Background(), func(tx store.ReadTx) error {
		n, err := tx.NetworkByName(net)
		if err != nil {
			return err
		}
		edges, err := tx.Edges(n.ID)
		for _, e := range edges {
			out = append(out, [2]model.InterfaceID{e.A, e.B})
		}
		return err
	}); err != nil {
		f.t.Fatal(err)
	}
	return out
}

func pairOf(a, b model.InterfaceID) [2]model.InterfaceID {
	x, y := compile.Pair(a, b)
	return [2]model.InterfaceID{x, y}
}

// TestAWildcardPeersEveryOtherServiceAndADenyCutsOneOut opens db to every
// service, then takes the sandboxes out with a deny, lets the sandboxes
// reach every service, and finally drops the deny: at each step each
// interface peers with exactly the interfaces policy connects it to, the
// sandboxes never with each other, and edges follow on both sides.
func TestAWildcardPeersEveryOtherServiceAndADenyCutsOneOut(t *testing.T) {
	eachStore(t, func(t *testing.T, f *fixture) {
		relay := f.relay("r")
		f.network(api.CreateNetwork{Name: "n", Relays: []model.RelayID{relay}})
		for _, s := range []string{"db", "web", "box"} {
			f.service("n", s, false)
		}
		db, _ := f.attach("h1", "n", "db")
		web, _ := f.attach("h2", "n", "web")
		box1, _ := f.attach("h2", "n", "box")
		box2, _ := f.attach("h3", "n", "box")
		// The rules come after the interfaces, so their edges come from the
		// wildcard's own reconciliation. The deny comes first: a pair a
		// rule disconnects keeps its edge through the port quarantine.
		boxOut, err := f.createRule("n", api.CreateRule{From: "box", To: "db", Proto: model.AnyProto, Action: api.Deny})
		if err != nil {
			t.Fatal(err)
		}
		f.rule("n", api.Wildcard, "db", model.TCP, 5432)
		check := func(step string, want map[model.InterfaceID][]model.InterfaceID, edges [][2]model.InterfaceID) {
			t.Helper()
			for id, peers := range want {
				host := map[model.InterfaceID]string{db.ID: "h1", web.ID: "h2", box1.ID: "h2", box2.ID: "h3"}[id]
				if got := peerIDs(f.state(host), id); !slices.Equal(got, sortedIDs(peers...)) {
					t.Fatalf("%s: %s peers %v, want %v", step, id, got, sortedIDs(peers...))
				}
			}
			got := f.edgePairs("n")
			slices.SortFunc(got, cmpPair)
			slices.SortFunc(edges, cmpPair)
			if !slices.Equal(got, edges) {
				t.Fatalf("%s: edges %v, want %v", step, got, edges)
			}
		}
		check("db open to all but the sandboxes", map[model.InterfaceID][]model.InterfaceID{
			db.ID: {web.ID}, web.ID: {db.ID}, box1.ID: nil, box2.ID: nil,
		}, [][2]model.InterfaceID{pairOf(db.ID, web.ID)})

		f.rule("n", "box", api.Wildcard, model.TCP, 443)
		check("the sandboxes reach every other service", map[model.InterfaceID][]model.InterfaceID{
			db.ID: {web.ID}, web.ID: {db.ID, box1.ID, box2.ID}, box1.ID: {web.ID}, box2.ID: {web.ID},
		}, [][2]model.InterfaceID{pairOf(db.ID, web.ID), pairOf(web.ID, box2.ID)})

		f.update(func(tx store.Tx) error { return f.p.DeleteRule(tx, f.now, Global(), "n", boxOut.ID) })
		check("the deny gone", map[model.InterfaceID][]model.InterfaceID{
			db.ID: {web.ID, box1.ID, box2.ID}, web.ID: {db.ID, box1.ID, box2.ID}, box1.ID: {db.ID, web.ID}, box2.ID: {db.ID, web.ID},
		}, [][2]model.InterfaceID{pairOf(db.ID, web.ID), pairOf(web.ID, box2.ID), pairOf(db.ID, box1.ID), pairOf(db.ID, box2.ID)})

		// The receiver admits exactly what the rules leave: TCP 5432 from
		// every other service, TCP 443 from the sandboxes, nothing from db.
		want := []api.Inbound{
			{From: web.Service, Proto: model.TCP, Ports: model.PortRange{Lo: 5432, Hi: 5432}},
			{From: box1.Service, Proto: model.TCP, Ports: model.PortRange{Lo: 443, Hi: 443}},
			{From: box1.Service, Proto: model.TCP, Ports: model.PortRange{Lo: 5432, Hi: 5432}},
		}
		slices.SortFunc(want, func(a, b api.Inbound) int {
			return cmp.Or(cmp.Compare(a.From, b.From), cmp.Compare(a.Ports.Lo, b.Ports.Lo))
		})
		for _, n := range f.state("h1").Networks {
			if x, _ := n.Interface(db.ID); !slices.Equal(x.Inbound, want) {
				t.Fatalf("db admits %+v, want %+v", x.Inbound, want)
			}
		}
	})
}

func cmpPair(a, b [2]model.InterfaceID) int {
	return cmp.Or(cmp.Compare(a[0], b[0]), cmp.Compare(a[1], b[1]))
}

func TestARuleIsCheckedAndStoredOnceForEachAction(t *testing.T) {
	eachStore(t, func(t *testing.T, f *fixture) {
		f.network(api.CreateNetwork{Name: "n"})
		f.service("n", "a", false)
		for _, c := range []struct {
			name string
			req  api.CreateRule
		}{
			{"an unknown action", api.CreateRule{From: "a", To: "a", Proto: model.TCP, Action: "drop"}},
			{"the internet as a source", api.CreateRule{From: api.Internet, To: "a", Proto: model.TCP}},
			{"a service the network lacks", api.CreateRule{From: api.Wildcard, To: "b", Proto: model.TCP}},
			{"a protocol rules cannot name", api.CreateRule{From: "a", To: "a", Proto: model.OtherProto}},
		} {
			if _, err := f.createRule("n", c.req); err == nil {
				t.Errorf("%s: created", c.name)
			}
		}
		allowAll, err := f.createRule("n", api.CreateRule{From: api.Wildcard, To: api.Internet, Proto: model.TCP, Ports: model.PortRange{Lo: 443, Hi: 443}})
		if err != nil {
			t.Fatal(err)
		}
		if allowAll.From != model.AnyService || allowAll.To != "" || allowAll.Deny {
			t.Fatalf("stored %+v", allowAll)
		}
		again, _ := f.createRule("n", api.CreateRule{From: api.Wildcard, To: api.Internet, Proto: model.TCP, Ports: model.PortRange{Lo: 443, Hi: 443}, Action: api.Allow})
		denied, err := f.createRule("n", api.CreateRule{From: api.Wildcard, To: api.Internet, Proto: model.TCP, Ports: model.PortRange{Lo: 443, Hi: 443}, Action: api.Deny})
		if err != nil {
			t.Fatal(err)
		}
		if again.ID != allowAll.ID || denied.ID == allowAll.ID || !denied.Deny {
			t.Fatalf("allow %s, the same allow %s, its deny %s (deny=%v): want the allow once and the deny apart", allowAll.ID, again.ID, denied.ID, denied.Deny)
		}
		var apiErr *api.Error
		_, err = f.createRule("n", api.CreateRule{From: "a", To: "a", Proto: model.TCP, Action: "drop"})
		if !errors.As(err, &apiErr) || apiErr.Code != api.CodeInvalid {
			t.Fatalf("an unknown action: %v, want an invalid-request error", err)
		}
	})
}

// TestEachScopeListsThePairsItCovers checks every kind of scope against a
// walk of every pair: each covered pair once, ordered as an edge stores it.
func TestEachScopeListsThePairsItCovers(t *testing.T) {
	rng := prng.New(3)
	svcs := []model.ServiceID{"a", "b", "c"}
	for round := range 200 {
		var connected []store.Interface
		for i := range rng.Index(12) {
			connected = append(connected, store.Interface{ID: model.InterfaceID(fmt.Sprintf("if-%02d", i)), Service: svcs[rng.Index(len(svcs))]})
		}
		for _, sc := range []scope{networkScope(), interfaceScope("if-03"), serviceScope("a"), servicesScope("a", "b"), servicesScope("c", "c")} {
			var want [][2]model.InterfaceID
			for i, x := range connected {
				for _, y := range connected[i+1:] {
					if sc.covers(x, y) {
						want = append(want, [2]model.InterfaceID{x.ID, y.ID})
					}
				}
			}
			var got [][2]model.InterfaceID
			for _, p := range sc.pairs(connected) {
				got = append(got, [2]model.InterfaceID{p[0].ID, p[1].ID})
			}
			slices.SortFunc(got, cmpPair)
			if !slices.Equal(got, want) {
				t.Fatalf("round %d, scope %+v: pairs %v, want %v", round, sc, got, want)
			}
		}
	}
}

// TestAHostLearnsTheAddressesOfServicesNoneOfItsInterfacesReach checks
// that each host's state names every service its interfaces reach and
// lists every other service's addresses, and that a deny moves db from
// one to the other on the sandboxes' host.
func TestAHostLearnsTheAddressesOfServicesNoneOfItsInterfacesReach(t *testing.T) {
	eachStore(t, func(t *testing.T, f *fixture) {
		f.network(api.CreateNetwork{Name: "n", Prefix4: netip.MustParsePrefix("10.42.0.0/16")})
		db := f.service("n", "db", true)
		box := f.service("n", "box", false)
		other := f.service("n", "other", false)
		f.rule("n", "*", "db", model.TCP, 5432)
		f.attach("h1", "n", "box")
		f.attach("h2", "n", "db")
		split := func(host string) (services []model.ServiceID, unreached []netip.Addr) {
			t.Helper()
			for _, n := range f.state(host).Networks {
				for _, s := range n.Services {
					services = append(services, s.ID)
				}
				unreached = append(unreached, n.Unreached...)
			}
			return services, unreached
		}
		sorted := func(as ...netip.Addr) []netip.Addr { slices.SortFunc(as, netip.Addr.Compare); return as }
		if svcs, un := split("h1"); !slices.Equal(svcs, []model.ServiceID{db.ID}) || !slices.Equal(un, sorted(box.Addr6, other.Addr6)) {
			t.Fatalf("h1 holds services %v and unreached %v", svcs, un)
		}
		if svcs, un := split("h2"); len(svcs) != 0 || !slices.Equal(un, sorted(db.Addr6, db.Addr4, box.Addr6, other.Addr6)) {
			t.Fatalf("h2 holds services %v and unreached %v", svcs, un)
		}
		f.createRule("n", api.CreateRule{From: "box", To: "db", Action: api.Deny, Proto: model.AnyProto})
		if svcs, un := split("h1"); len(svcs) != 0 || !slices.Equal(un, sorted(db.Addr6, db.Addr4, box.Addr6, other.Addr6)) {
			t.Fatalf("after the deny h1 holds services %v and unreached %v", svcs, un)
		}
	})
}

// TestTheSideThatReachesKeepsALoopbackPairAlive puts sandboxes on db's host
// under `box -> db`: each sandbox's peer for db carries keepalive and db's
// for it does not, whichever has the lower ID, so a sandbox's first
// connection and its keepalive start from one device.
func TestTheSideThatReachesKeepsALoopbackPairAlive(t *testing.T) {
	eachStore(t, func(t *testing.T, f *fixture) {
		f.network(api.CreateNetwork{Name: "n"})
		f.service("n", "db", false)
		f.service("n", "box", false)
		f.rule("n", "box", "db", model.TCP, 5432)
		db, _ := f.attach("h1", "n", "db")
		var boxes []store.Interface
		for range 6 {
			b, _ := f.attach("h1", "n", "box")
			boxes = append(boxes, b)
		}
		keeps := func(x, y store.Interface) bool {
			t.Helper()
			for _, n := range f.state("h1").Networks {
				xi, _ := n.Interface(x.ID)
				for _, p := range xi.Peers {
					if p.Interface == y.ID {
						return p.Keepalive
					}
				}
			}
			t.Fatalf("%s holds no peer for %s", x.ID, y.ID)
			return false
		}
		higher := false
		for _, b := range boxes {
			higher = higher || db.ID < b.ID
			if !keeps(b, db) || keeps(db, b) {
				t.Errorf("%s toward db %v, db toward it %v: want the sandbox alone", b.ID, keeps(b, db), keeps(db, b))
			}
		}
		if !higher {
			t.Fatal("no sandbox drew an identifier above db's, where the lower ID alone would arm db, so the test proves nothing")
		}
	})
}
