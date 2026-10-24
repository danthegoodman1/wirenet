package cp

import (
	"net/netip"
	"slices"
	"testing"
	"time"

	"github.com/danthegoodman1/wirenet/internal/api"
	"github.com/danthegoodman1/wirenet/internal/model"
	"github.com/danthegoodman1/wirenet/internal/store"
)

// scopedHost registers a host scoped by a principal of scope by.
func (f *fixture) scopedHost(name string, by store.Scope, nets ...string) (store.Host, error) {
	var h store.Host
	err := f.tryUpdate(func(tx store.Tx) error {
		var err error
		h, _, err = f.p.CreateHost(tx, f.now, by, api.CreateHost{Name: name, Endpoint: edgeEndpoint, Networks: nets})
		return err
	})
	if err == nil {
		f.hosts[name] = h.ID
	}
	return h, err
}

// attachTo attaches a workload on a host and returns the error the plane
// answers.
func (f *fixture) attachTo(host model.HostID, net, svc string) (store.Interface, error) {
	priv, _ := model.NewPrivateKey(f.rng)
	id, _ := model.NewID(model.InterfacePrefix, f.rng)
	var i store.Interface
	err := f.tryUpdate(func(tx store.Tx) error {
		var err error
		i, _, err = f.p.Attach(tx, f.now, host, api.AttachRequest{
			Interface: model.InterfaceID(id), Network: net, Service: svc,
			PublicKey: priv.Public(), ListenPort: uint16(40000 + f.rng.Below(1000)),
		})
		return err
	})
	return i, err
}

func (f *fixture) networkID(name string) model.NetworkID {
	f.t.Helper()
	var n store.Network
	f.view(func(tx store.ReadTx) error {
		var err error
		n, err = tx.NetworkByName(name)
		return err
	})
	return n.ID
}

func (f *fixture) revision(net string) uint64 {
	f.t.Helper()
	var n store.Network
	f.view(func(tx store.ReadTx) error {
		var err error
		n, err = ResolveNetwork(tx, net)
		return err
	})
	return n.Revision
}

func scopeOf(ids ...model.NetworkID) store.Scope {
	slices.Sort(ids)
	return store.Scope{Networks: ids}
}

// TestAScopedHostAttachesOnlyIntoItsNetworks checks that a host's scope
// bounds its attaches, that a network outside it answers as a missing one
// does, and that a network created again under a scoped name falls outside.
func TestAScopedHostAttachesOnlyIntoItsNetworks(t *testing.T) {
	eachStore(t, func(t *testing.T, f *fixture) {
		for _, net := range []string{"shop", "bank"} {
			f.network(api.CreateNetwork{Name: net})
			f.service(net, "web", false)
		}
		h, err := f.scopedHost("tenant", Global(), "shop")
		if err != nil {
			t.Fatal(err)
		}
		if want := scopeOf(f.networkID("shop")); !slices.Equal(h.Scope.Networks, want.Networks) || h.Scope.Global {
			t.Fatalf("the host's scope is %+v, want %+v", h.Scope, want)
		}
		if _, err := f.attachTo(h.ID, "shop", "web"); err != nil {
			t.Fatalf("attach into its own network: %v", err)
		}
		before := f.revision("bank")
		_, outside := f.attachTo(h.ID, "bank", "web")
		_, missing := f.attachTo(h.ID, "nowhere", "web")
		if code(outside) != api.CodeNotFound || code(missing) != api.CodeNotFound {
			t.Fatalf("attach outside the scope: %v; into no network: %v", outside, missing)
		}
		if outside.Error() != "not_found: network bank not found" {
			t.Fatalf("a network outside the scope answers %q, unlike a missing one", outside)
		}
		if _, err := f.attachTo(h.ID, string(f.networkID("bank")), "web"); code(err) != api.CodeNotFound {
			t.Fatalf("attach by identifier outside the scope: %v", err)
		}
		if f.revision("bank") != before {
			t.Fatal("a refused attach moved the other network's revision")
		}
		global := f.host("operator-host")
		if _, err := f.attachTo(global, "bank", "web"); err != nil {
			t.Fatalf("a global host's attach: %v", err)
		}

		// A network deleted and created again under the scoped name is a
		// new network, which the old scope does not admit.
		f.network(api.CreateNetwork{Name: "spare"})
		f.service("spare", "web", false)
		spare, err := f.scopedHost("spare-tenant", Global(), "spare")
		if err != nil {
			t.Fatal(err)
		}
		f.update(func(tx store.Tx) error { return f.p.DeleteNetwork(tx, "spare") })
		f.network(api.CreateNetwork{Name: "spare"})
		f.service("spare", "web", false)
		if _, err := f.attachTo(spare.ID, "spare", "web"); code(err) != api.CodeNotFound {
			t.Fatalf("attach into a network made again under its scope's name: %v", err)
		}
	})
}

// TestAHostThatAdmitsNothingAttachesNowhere checks that an emptied scope
// stays empty rather than reading as global.
func TestAHostThatAdmitsNothingAttachesNowhere(t *testing.T) {
	eachStore(t, func(t *testing.T, f *fixture) {
		f.network(api.CreateNetwork{Name: "shop"})
		f.service("shop", "web", false)
		h, err := f.scopedHost("tenant", Global(), "shop")
		if err != nil {
			t.Fatal(err)
		}
		f.update(func(tx store.Tx) error {
			_, _, err := f.p.SetHostScope(tx, f.now, Global(), "tenant", api.Scope{})
			return err
		})
		if _, err := f.attachTo(h.ID, "shop", "web"); code(err) != api.CodeNotFound {
			t.Fatalf("a host that admits nothing attached: %v", err)
		}
	})
}

// TestRescopingAHostRevokesItsInterfacesInTheNetworksItLoses checks that a
// scope change fences what it removes, development machines behind a lost
// gateway included, and leaves the rest live.
func TestRescopingAHostRevokesItsInterfacesInTheNetworksItLoses(t *testing.T) {
	eachStore(t, func(t *testing.T, f *fixture) {
		gw, db, _ := shopWithDevices(f)
		laptop, err := f.device("shop", "dev", gw.ID, 24*time.Hour)
		if err != nil {
			t.Fatal(err)
		}
		f.network(api.CreateNetwork{Name: "bank"})
		f.service("bank", "web", false)
		kept, err := f.attachTo(f.hosts["edge"], "bank", "web")
		if err != nil {
			t.Fatal(err)
		}
		if got := peerIDs(f.state("h2"), db.ID); !slices.Contains(got, gw.ID) {
			t.Fatalf("db's peers before the rescope: %v", got)
		}
		var h store.Host
		var revoked []model.InterfaceID
		f.update(func(tx store.Tx) error {
			var err error
			h, revoked, err = f.p.SetHostScope(tx, f.now, Global(), "edge", api.Scope{Networks: []string{"bank"}})
			return err
		})
		if !slices.Equal(revoked, []model.InterfaceID{gw.ID}) {
			t.Fatalf("the rescope reports revoking %v, want the gateway alone", revoked)
		}
		if want := scopeOf(f.networkID("bank")); !slices.Equal(h.Scope.Networks, want.Networks) {
			t.Fatalf("the host's scope is %+v", h.Scope)
		}
		for _, id := range []model.InterfaceID{gw.ID, laptop.ID} {
			if st := f.interfaceState(id); st != api.Revoked {
				t.Fatalf("%s is %s after its host lost its network", id, st)
			}
		}
		if st := f.interfaceState(kept.ID); st != api.Live {
			t.Fatalf("the interface in the network the host kept is %s", st)
		}
		if got := peerIDs(f.state("h2"), db.ID); slices.Contains(got, gw.ID) {
			t.Fatalf("db still peers with the revoked gateway: %v", got)
		}
		if _, err := f.attachTo(h.ID, "shop", "edge"); code(err) != api.CodeNotFound {
			t.Fatalf("an attach into the lost network: %v", err)
		}
	})
}

// TestAScopedPrincipalManagesOnlyHostsWithinItsScope checks every rule a
// scoped admin's hosts follow.
func TestAScopedPrincipalManagesOnlyHostsWithinItsScope(t *testing.T) {
	eachStore(t, func(t *testing.T, f *fixture) {
		for _, net := range []string{"shop", "bank"} {
			f.network(api.CreateNetwork{Name: net})
		}
		shop := f.networkID("shop")
		tenant := scopeOf(shop)
		if _, err := f.scopedHost("global-try", tenant); code(err) != api.CodeForbidden {
			t.Fatalf("a scoped admin registering a global host: %v", err)
		}
		if _, err := f.scopedHost("outside", tenant, "bank"); code(err) != api.CodeNotFound {
			t.Fatalf("a scoped admin naming another tenant's network: %v", err)
		}
		if _, err := f.scopedHost("mine", tenant, "shop", string(shop)); err != nil {
			t.Fatalf("a scoped admin registering a host in its network: %v", err)
		}
		if _, err := f.scopedHost("both", Global(), "shop", "bank"); err != nil {
			t.Fatal(err)
		}
		if _, err := f.scopedHost("empty", Global(), "shop"); err != nil {
			t.Fatal(err)
		}
		f.update(func(tx store.Tx) error {
			_, _, err := f.p.SetHostScope(tx, f.now, Global(), "empty", api.Scope{})
			return err
		})
		f.host("global")

		var hosts []store.Host
		f.view(func(tx store.ReadTx) error {
			var err error
			hosts, err = HostsIn(tx, tenant)
			return err
		})
		if len(hosts) != 1 || hosts[0].Name != "mine" {
			t.Fatalf("the scoped admin lists %v", hosts)
		}
		if !slices.Equal(hosts[0].Scope.Networks, []model.NetworkID{shop}) {
			t.Fatalf("a repeated network was kept: %v", hosts[0].Scope.Networks)
		}
		for _, name := range []string{"both", "empty", "global"} {
			err := f.tryUpdate(func(tx store.Tx) error { _, err := f.p.DeleteHost(tx, f.now, tenant, name); return err })
			if code(err) != api.CodeNotFound {
				t.Fatalf("the scoped admin deleting host %s: %v", name, err)
			}
			err = f.tryUpdate(func(tx store.Tx) error {
				_, _, err := f.p.SetHostScope(tx, f.now, tenant, name, api.Scope{Networks: []string{"shop"}})
				return err
			})
			if code(err) != api.CodeNotFound {
				t.Fatalf("the scoped admin rescoping host %s: %v", name, err)
			}
		}
		for _, sc := range []api.Scope{{Global: true}, {}, {Networks: []string{"bank"}}} {
			err := f.tryUpdate(func(tx store.Tx) error { _, _, err := f.p.SetHostScope(tx, f.now, tenant, "mine", sc); return err })
			if code(err) != api.CodeForbidden && code(err) != api.CodeNotFound {
				t.Fatalf("the scoped admin rescoping its host to %+v: %v", sc, err)
			}
		}
		err := f.tryUpdate(func(tx store.Tx) error {
			_, _, err := f.p.SetHostScope(tx, f.now, Global(), "mine", api.Scope{Global: true, Networks: []string{"shop"}})
			return err
		})
		if code(err) != api.CodeInvalid {
			t.Fatalf("a global scope listing networks: %v", err)
		}
		f.update(func(tx store.Tx) error { _, err := f.p.DeleteHost(tx, f.now, tenant, "mine"); return err })
	})
}

// TestAnAdminTokenManagesTheNetworksItNames checks issuing, rescoping and
// deleting admin tokens.
func TestAnAdminTokenManagesTheNetworksItNames(t *testing.T) {
	eachStore(t, func(t *testing.T, f *fixture) {
		for _, net := range []string{"shop", "bank"} {
			f.network(api.CreateNetwork{Name: net})
		}
		create := func(name string, nets ...string) (store.Admin, string, error) {
			var a store.Admin
			var token string
			err := f.tryUpdate(func(tx store.Tx) error {
				var err error
				a, token, err = f.p.CreateAdmin(tx, f.now, api.CreateAdmin{Name: name, Networks: nets})
				return err
			})
			return a, token, err
		}
		if _, _, err := create("none"); code(err) != api.CodeInvalid {
			t.Fatalf("an admin token naming no network: %v", err)
		}
		if _, _, err := create("lost", "nowhere"); code(err) != api.CodeNotFound {
			t.Fatalf("an admin token naming a missing network: %v", err)
		}
		a, token, err := create("tenant", "shop", "shop")
		if err != nil {
			t.Fatal(err)
		}
		if a.Scope.Global || !slices.Equal(a.Scope.Networks, []model.NetworkID{f.networkID("shop")}) || a.TokenHash != HashToken(token) {
			t.Fatalf("the admin is %+v", a)
		}
		if _, _, err := create("tenant", "bank"); code(err) != api.CodeConflict {
			t.Fatalf("a second admin under one name: %v", err)
		}
		f.update(func(tx store.Tx) error {
			var err error
			a, err = f.p.SetAdminScope(tx, "tenant", []string{"bank", "shop"})
			return err
		})
		if want := scopeOf(f.networkID("bank"), f.networkID("shop")); !slices.Equal(a.Scope.Networks, want.Networks) {
			t.Fatalf("the rescoped admin holds %v", a.Scope.Networks)
		}
		err = f.tryUpdate(func(tx store.Tx) error { _, err := f.p.SetAdminScope(tx, "tenant", nil); return err })
		if code(err) != api.CodeInvalid {
			t.Fatalf("rescoping an admin to no network: %v", err)
		}
		f.update(func(tx store.Tx) error { _, err := f.p.DeleteAdmin(tx, string(a.ID)); return err })
		f.view(func(tx store.ReadTx) error {
			if _, err := tx.AdminByToken(HashToken(token)); err != store.ErrNotFound {
				t.Errorf("the deleted admin's token: %v", err)
			}
			return nil
		})
	})
}

// TestAQuotaRefusesGrowthAndChangesNothing checks each bound: the change
// that would pass it fails whole, and a bound lowered below what the
// network holds stops growth and nothing else.
func TestAQuotaRefusesGrowthAndChangesNothing(t *testing.T) {
	eachStore(t, func(t *testing.T, f *fixture) {
		relay := f.relay("r")
		f.network(api.CreateNetwork{
			Name: "shop", Prefix4: netip.MustParsePrefix("10.42.0.0/16"), Relays: []model.RelayID{relay},
			Quota: api.Quota{Interfaces: 3, Services: 3, Rules: 2, Edges: 2},
		})
		usage := func() api.Quota {
			var u api.Quota
			f.view(func(tx store.ReadTx) error {
				n, err := tx.NetworkByName("shop")
				if err != nil {
					return err
				}
				u, err = Usage(tx, n)
				return err
			})
			return u
		}
		refused := func(what string, err error) {
			t.Helper()
			if code(err) != api.CodeExhausted {
				t.Fatalf("%s past the quota: %v", what, err)
			}
		}
		for _, svc := range []string{"web", "db", "cache"} {
			f.service("shop", svc, true)
		}
		err := f.tryUpdate(func(tx store.Tx) error {
			_, err := f.p.CreateService(tx, f.now, Global(), "shop", api.CreateService{Name: "extra"})
			return err
		})
		refused("a fourth service", err)

		f.rule("shop", "web", "db", model.TCP, 5432)
		_, err = f.createRule("shop", api.CreateRule{From: "web", To: "cache", Proto: model.TCP, Ports: model.PortRange{Lo: 6379, Hi: 6379}})
		if err != nil {
			t.Fatal(err)
		}
		_, err = f.createRule("shop", api.CreateRule{From: "db", To: "cache", Proto: model.TCP, Ports: model.PortRange{Lo: 6379, Hi: 6379}})
		refused("a third rule", err)
		if _, err := f.createRule("shop", api.CreateRule{From: "web", To: "db", Proto: model.TCP, Ports: model.PortRange{Lo: 5432, Hi: 5432}}); err != nil {
			t.Fatalf("a rule the network already holds: %v", err)
		}

		// web on h1 reaches db and cache on h2: two edges.
		f.attach("h2", "shop", "db")
		f.attach("h2", "shop", "cache")
		f.attach("h1", "shop", "web")
		before, rev := usage(), f.revision("shop")
		if before != (api.Quota{Interfaces: 3, Services: 3, Rules: 2, Edges: 2}) {
			t.Fatalf("the network holds %+v", before)
		}
		_, err = f.attachTo(f.host("h3"), "shop", "web")
		refused("a fourth interface", err)
		if usage() != before || f.revision("shop") != rev {
			t.Fatalf("a refused attach changed the network: %+v, revision %d to %d", usage(), rev, f.revision("shop"))
		}

		// With room for interfaces, the edge bound refuses the attach.
		f.update(func(tx store.Tx) error {
			_, err := f.p.SetQuota(tx, "shop", api.Quota{Interfaces: 10, Services: 3, Rules: 2, Edges: 2})
			return err
		})
		_, err = f.attachTo(f.host("h3"), "shop", "web")
		refused("an attach adding edges", err)
		if usage() != before {
			t.Fatalf("a refused attach changed the network: %+v", usage())
		}
		// A co-located web peers with no relay, so it adds no edge.
		if _, err := f.attachTo(f.host("h2"), "shop", "web"); err != nil {
			t.Fatalf("an attach adding no edge: %v", err)
		}

		// An edge bound lowered below what the network holds lets in an
		// attach that adds no edge.
		f.update(func(tx store.Tx) error {
			_, err := f.p.SetQuota(tx, "shop", api.Quota{Interfaces: 10, Services: 3, Rules: 2, Edges: 1})
			return err
		})
		if _, err := f.attachTo(f.host("h2"), "shop", "web"); err != nil {
			t.Fatalf("an attach adding no edge under a lowered edge bound: %v", err)
		}

		// A bound lowered below what the network holds stops growth and
		// lets it shrink.
		f.update(func(tx store.Tx) error {
			_, err := f.p.SetQuota(tx, "shop", api.Quota{Interfaces: 1, Services: 1, Rules: 1, Edges: 1})
			return err
		})
		_, err = f.attachTo(f.host("h2"), "shop", "web")
		refused("an attach under a lowered bound", err)
		var rules []store.Rule
		f.view(func(tx store.ReadTx) error {
			var err error
			rules, err = tx.Rules(f.networkID("shop"))
			return err
		})
		f.update(func(tx store.Tx) error { return f.p.DeleteRule(tx, f.now, Global(), "shop", rules[0].ID) })
		if got := usage(); got.Rules != 1 {
			t.Fatalf("after a removal under a lowered bound the network holds %+v", got)
		}
	})
}

// TestAReplacementAtTheInterfaceBoundTakesItsHoldersPlace checks that a
// replacing attach, which revokes the member's holder, fits a full quota.
func TestAReplacementAtTheInterfaceBoundTakesItsHoldersPlace(t *testing.T) {
	eachStore(t, func(t *testing.T, f *fixture) {
		f.network(api.CreateNetwork{Name: "shop", Quota: api.Quota{Interfaces: 1}})
		f.service("shop", "etcd", false)
		f.member("h1", "shop", "etcd", "etcd-1", false)
		if _, _, err := f.tryAttach(f.memberRequest("h2", "shop", "etcd", "etcd-2", false)); code(err) != api.CodeExhausted {
			t.Fatalf("a second member past the quota: %v", err)
		}
		if _, replaced := f.member("h2", "shop", "etcd", "etcd-1", true); replaced == "" {
			t.Fatal("the replacement replaced nothing")
		}
	})
}

// TestANetworkTakesTheDefaultForEachBoundItLeavesOut checks where a
// network's quota comes from: its creation's bounds over the control
// plane's defaults, and a replacement that leaves a bound out unbounding it.
func TestANetworkTakesTheDefaultForEachBoundItLeavesOut(t *testing.T) {
	eachStore(t, func(t *testing.T, f *fixture) {
		f.p.Config.Quota = api.Quota{Interfaces: 100, Edges: 1000}
		if got := f.network(api.CreateNetwork{Name: "plain"}).Quota; got != f.p.Config.Quota {
			t.Fatalf("a network naming no bound holds %+v", got)
		}
		if got := f.network(api.CreateNetwork{Name: "some", Quota: api.Quota{Rules: 5, Edges: 50}}).Quota; got != (api.Quota{Interfaces: 100, Rules: 5, Edges: 50}) {
			t.Fatalf("a network naming two bounds holds %+v", got)
		}
		var n store.Network
		f.update(func(tx store.Tx) error {
			var err error
			n, err = f.p.SetQuota(tx, "some", api.Quota{Rules: 5})
			return err
		})
		if n.Quota != (api.Quota{Rules: 5}) {
			t.Fatalf("a replaced quota holds %+v", n.Quota)
		}
		err := f.tryUpdate(func(tx store.Tx) error {
			_, err := f.p.CreateNetwork(tx, f.now, api.CreateNetwork{Name: "bad", Quota: api.Quota{Rules: -1}})
			return err
		})
		if code(err) != api.CodeInvalid {
			t.Fatalf("a negative bound: %v", err)
		}
	})
}

// TestADeletedNetworkLeavesEveryScope checks that a network's deletion
// takes it out of host and admin scopes, so an admin keeps managing a host
// whose other network went, and a list emptied admits nothing.
func TestADeletedNetworkLeavesEveryScope(t *testing.T) {
	eachStore(t, func(t *testing.T, f *fixture) {
		for _, net := range []string{"shop", "lab"} {
			f.network(api.CreateNetwork{Name: net})
		}
		shop := f.networkID("shop")
		var a store.Admin
		f.update(func(tx store.Tx) error {
			var err error
			a, _, err = f.p.CreateAdmin(tx, f.now, api.CreateAdmin{Name: "tenant", Networks: []string{"shop", "lab"}})
			return err
		})
		if _, err := f.scopedHost("both", Global(), "shop", "lab"); err != nil {
			t.Fatal(err)
		}
		if _, err := f.scopedHost("lab-only", Global(), "lab"); err != nil {
			t.Fatal(err)
		}
		f.update(func(tx store.Tx) error { return f.p.DeleteNetwork(tx, "lab") })
		f.view(func(tx store.ReadTx) error {
			both, err := tx.HostByName("both")
			if err != nil {
				return err
			}
			if !slices.Equal(both.Scope.Networks, []model.NetworkID{shop}) {
				t.Errorf("the host's scope after the deletion: %+v", both.Scope)
			}
			only, err := tx.HostByName("lab-only")
			if err != nil {
				return err
			}
			if only.Scope.Global || only.Scope.Networks != nil {
				t.Errorf("the emptied host's scope: %+v", only.Scope)
			}
			admin, err := tx.Admin(a.ID)
			if err != nil {
				return err
			}
			if !slices.Equal(admin.Scope.Networks, []model.NetworkID{shop}) {
				t.Errorf("the admin's scope after the deletion: %+v", admin.Scope)
			}
			hosts, err := HostsIn(tx, admin.Scope)
			if err != nil {
				return err
			}
			if len(hosts) != 1 || hosts[0].Name != "both" {
				t.Errorf("the admin manages %v", hosts)
			}
			return nil
		})
	})
}

// TestAScopedCallerNarrowsEgressAndNeverWidensIt checks the egress rules a
// scoped caller may write: a deny, and the removal of an allow, and not an
// allow or the removal of a deny.
func TestAScopedCallerNarrowsEgressAndNeverWidensIt(t *testing.T) {
	eachStore(t, func(t *testing.T, f *fixture) {
		f.network(api.CreateNetwork{Name: "shop"})
		f.service("shop", "web", false)
		f.service("shop", "secret", false)
		shop := scopeOf(f.networkID("shop"))
		allow, err := f.createRuleBy(Global(), "shop", api.CreateRule{From: api.Wildcard, To: api.Internet, Proto: model.TCP})
		if err != nil {
			t.Fatal(err)
		}
		deny, err := f.createRuleBy(Global(), "shop", api.CreateRule{From: "secret", To: api.Internet, Proto: model.AnyProto, Action: api.Deny})
		if err != nil {
			t.Fatal(err)
		}
		if _, err := f.createRuleBy(shop, "shop", api.CreateRule{From: "web", To: api.Internet, Proto: model.UDP, Action: api.Deny}); err != nil {
			t.Fatalf("a scoped caller's egress deny: %v", err)
		}
		if err := f.tryUpdate(func(tx store.Tx) error { return f.p.DeleteRule(tx, f.now, shop, "shop", deny.ID) }); code(err) != api.CodeForbidden {
			t.Fatalf("a scoped caller lifting an egress deny: %v", err)
		}
		if err := f.tryUpdate(func(tx store.Tx) error { return f.p.DeleteRule(tx, f.now, shop, "shop", allow.ID) }); err != nil {
			t.Fatalf("a scoped caller removing an egress allow: %v", err)
		}
	})
}

// TestDeletingADenyPastTheEdgeBoundFails builds a network whose deny holds
// every pair apart, then checks that deleting the deny, which would connect
// them past the edge bound, fails and changes nothing.
func TestDeletingADenyPastTheEdgeBoundFails(t *testing.T) {
	eachStore(t, func(t *testing.T, f *fixture) {
		relay := f.relay("r")
		f.network(api.CreateNetwork{Name: "shop", Relays: []model.RelayID{relay}, Quota: api.Quota{Edges: 1}})
		f.service("shop", "web", false)
		f.service("shop", "db", false)
		f.rule("shop", "web", "db", model.TCP, 5432)
		deny, err := f.createRule("shop", api.CreateRule{From: "web", To: "db", Proto: model.AnyProto, Action: api.Deny})
		if err != nil {
			t.Fatal(err)
		}
		for _, h := range []string{"h1", "h2"} {
			f.attach(h, "shop", "web")
		}
		f.attach("h3", "shop", "db")
		if got := f.edgePairs("shop"); len(got) != 0 {
			t.Fatalf("the deny left edges %v", got)
		}
		err = f.tryUpdate(func(tx store.Tx) error { return f.p.DeleteRule(tx, f.now, Global(), "shop", deny.ID) })
		if code(err) != api.CodeExhausted {
			t.Fatalf("deleting the deny past the edge bound: %v", err)
		}
		if got := f.edgePairs("shop"); len(got) != 0 {
			t.Fatalf("the refused deletion left edges %v", got)
		}
	})
}

// TestRescopingRevokesADrainingInterface checks that an interface still
// draining on its peers goes with the network its host loses.
func TestRescopingRevokesADrainingInterface(t *testing.T) {
	eachStore(t, func(t *testing.T, f *fixture) {
		f.network(api.CreateNetwork{Name: "shop"})
		f.service("shop", "web", false)
		i, _ := f.attach("h1", "shop", "web")
		f.update(func(tx store.Tx) error { return f.p.Release(tx, f.now, f.host("h1"), []model.InterfaceID{i.ID}) })
		if st := f.interfaceState(i.ID); st != api.Released {
			t.Fatalf("the released interface is %s", st)
		}
		f.update(func(tx store.Tx) error {
			_, _, err := f.p.SetHostScope(tx, f.now, Global(), "h1", api.Scope{})
			return err
		})
		if st := f.interfaceState(i.ID); st != api.Revoked {
			t.Fatalf("the draining interface is %s after its host lost the network", st)
		}
	})
}

// TestARescopedHostPollsOnlyItsScope follows an agent's polls through
// rescopes: a network the scope lost leaves the poll, though its revoked
// interface's record remains, so the host learns nothing of the services
// it gains; a rescope revoking nothing still moves the host past what it
// holds; and a network the scope regains returns with its state.
func TestARescopedHostPollsOnlyItsScope(t *testing.T) {
	eachStore(t, func(t *testing.T, f *fixture) {
		for _, net := range []string{"shop", "bank"} {
			f.network(api.CreateNetwork{Name: net})
			f.service(net, "web", false)
		}
		shop, bank := f.networkID("shop"), f.networkID("bank")
		agents := map[string]*api.HostState{}
		poll := func(host string) *api.HostState {
			t.Helper()
			a := agents[host]
			if a == nil {
				a = api.NewHostState()
				agents[host] = a
			}
			var u api.StateUpdate
			f.view(func(tx store.ReadTx) error {
				var err error
				u, err = HostState(tx, NoCache{}, f.host(host), a.Generation)
				return err
			})
			if err := a.Apply(u); err != nil {
				t.Fatalf("%s's agent applying its poll: %v", host, err)
			}
			return a
		}
		rescope := func(host string, nets ...string) []model.InterfaceID {
			t.Helper()
			var revoked []model.InterfaceID
			f.update(func(tx store.Tx) error {
				var err error
				_, revoked, err = f.p.SetHostScope(tx, f.now, Global(), host, api.Scope{Networks: nets})
				return err
			})
			return revoked
		}
		holds := func(a *api.HostState, want ...model.NetworkID) {
			t.Helper()
			slices.Sort(want)
			if got := a.NetworkIDs(); !slices.Equal(got, want) {
				t.Fatalf("the agent holds %v, want %v", got, want)
			}
		}

		gone, _ := f.attach("h1", "shop", "web")
		f.attach("h1", "bank", "web")
		holds(poll("h1"), shop, bank)
		rescope("h1", "bank")
		if st := f.interfaceState(gone.ID); st != api.Revoked {
			t.Fatalf("the interface in the lost network is %s", st)
		}
		// bank's change moves the agent past every revision shop has.
		f.service("shop", "db", false)
		f.service("bank", "db", false)
		holds(poll("h1"), bank)
		if u := f.state("h1"); len(u.Present) != 1 || u.Present[0].Network != bank {
			t.Fatalf("after losing shop the host polls %+v", u.Present)
		}
		rescope("h1", "shop", "bank")
		a := poll("h1")
		holds(a, shop, bank)
		if i, ok := a.Networks[shop].Interface(gone.ID); !ok || i.State != api.Revoked {
			t.Fatalf("the regained network carries the revoked interface as %+v", i)
		}

		// h2's interface is revoked while its host stays global, so its
		// poll keeps the network, which then moves past the host's own
		// revision.
		i, _ := f.attach("h2", "shop", "web")
		f.update(func(tx store.Tx) error { return f.p.Revoke(tx, f.now, i.ID) })
		f.service("shop", "cache", false)
		holds(poll("h2"), shop)
		if revoked := rescope("h2", "bank"); len(revoked) > 0 {
			t.Fatalf("the rescope revoked %v, with nothing live to revoke", revoked)
		}
		holds(poll("h2"))
	})
}

// TestAnAttachAnswerRefusesAnEndedInterface checks the attach's answer,
// read after its commit: it answers only the interface's own host, and once
// a rescope ends the interface it carries nothing of the network its host
// lost.
func TestAnAttachAnswerRefusesAnEndedInterface(t *testing.T) {
	eachStore(t, func(t *testing.T, f *fixture) {
		f.network(api.CreateNetwork{Name: "shop"})
		f.service("shop", "web", false)
		i, _ := f.attach("h1", "shop", "web")
		f.attach("h2", "shop", "web")
		answerTo := func(host string) (api.NetworkState, error) {
			var ns api.NetworkState
			var err error
			f.view(func(tx store.ReadTx) error {
				ns, err = AttachState(tx, NoCache{}, i.ID, f.host(host))
				return nil
			})
			return ns, err
		}
		answer := func() (api.NetworkState, error) { return answerTo("h1") }
		if ns, err := answer(); err != nil || ns.Network != i.Network {
			t.Fatalf("the live interface's answer: %+v, %v", ns, err)
		}
		if ns, err := answerTo("h2"); code(err) != api.CodeNotFound || ns.Network != "" {
			t.Fatalf("another host's answer for the interface: %+v, %v", ns, err)
		}
		f.update(func(tx store.Tx) error {
			_, _, err := f.p.SetHostScope(tx, f.now, Global(), "h1", api.Scope{})
			return err
		})
		f.service("shop", "db", false)
		if ns, err := answer(); code(err) != api.CodeConflict || ns.Network != "" {
			t.Fatalf("the answer after a rescope ended the interface: %+v, %v", ns, err)
		}
	})
}

// TestAScopedCallerFindsAnotherNetworksInterfacesAbsent checks a gateway
// and a revocation that name an interface of another network.
func TestAScopedCallerFindsAnotherNetworksInterfacesAbsent(t *testing.T) {
	eachStore(t, func(t *testing.T, f *fixture) {
		shopWithDevices(f)
		f.network(api.CreateNetwork{Name: "bank"})
		f.service("bank", "edge", false)
		bankGW := f.gateway("bank-edge", "bank", "edge")
		priv, _ := model.NewPrivateKey(f.rng)
		err := f.tryUpdate(func(tx store.Tx) error {
			_, err := f.p.CreateDevice(tx, f.now, Global(), "shop", api.CreateDevice{Service: "dev", Gateway: bankGW.ID, PublicKey: priv.Public(), TTL: time.Hour})
			return err
		})
		if code(err) != api.CodeNotFound {
			t.Fatalf("a device behind another network's gateway: %v", err)
		}
		shop := scopeOf(f.networkID("shop"))
		err = f.tryUpdate(func(tx store.Tx) error { return f.p.RevokeIn(tx, f.now, shop, bankGW.ID) })
		if code(err) != api.CodeNotFound || f.interfaceState(bankGW.ID) != api.Live {
			t.Fatalf("revoking another network's interface: %v, now %s", err, f.interfaceState(bankGW.ID))
		}
		web, _ := f.attach("h9", "shop", "dev")
		f.update(func(tx store.Tx) error { return f.p.RevokeIn(tx, f.now, shop, web.ID) })
		if st := f.interfaceState(web.ID); st != api.Revoked {
			t.Fatalf("revoking its own network's interface left it %s", st)
		}
		_, err = f.createRuleBy(shop, "shop", api.CreateRule{From: "dev", To: api.Internet, Proto: model.TCP})
		if code(err) != api.CodeForbidden {
			t.Fatalf("a scoped caller's egress rule: %v", err)
		}
	})
}

func (f *fixture) createRuleBy(by store.Scope, net string, req api.CreateRule) (store.Rule, error) {
	var r store.Rule
	err := f.tryUpdate(func(tx store.Tx) error {
		var err error
		r, err = f.p.CreateRule(tx, f.now, by, net, req)
		return err
	})
	return r, err
}

// TestAReplacementUnderALoweredEdgeBoundKeepsItsCount checks that a
// replacement that leaves the edge count where it was passes a bound
// lowered below it.
func TestAReplacementUnderALoweredEdgeBoundKeepsItsCount(t *testing.T) {
	eachStore(t, func(t *testing.T, f *fixture) {
		relay := f.relay("r")
		f.network(api.CreateNetwork{Name: "shop", Relays: []model.RelayID{relay}})
		f.service("shop", "etcd", false)
		f.service("shop", "web", false)
		f.rule("shop", "web", "etcd", model.TCP, 2379)
		for _, h := range []string{"h1", "h2", "h3"} {
			f.attach(h, "shop", "web")
		}
		f.member("h4", "shop", "etcd", "etcd-1", false)
		if got := len(f.edgePairs("shop")); got != 3 {
			t.Fatalf("the network holds %d edges, want 3", got)
		}
		f.update(func(tx store.Tx) error {
			_, err := f.p.SetQuota(tx, "shop", api.Quota{Edges: 2})
			return err
		})
		if _, replaced := f.member("h5", "shop", "etcd", "etcd-1", true); replaced == "" {
			t.Fatal("the replacement replaced nothing")
		}
		if got := len(f.edgePairs("shop")); got != 3 {
			t.Fatalf("after the replacement the network holds %d edges, want 3", got)
		}
	})
}
