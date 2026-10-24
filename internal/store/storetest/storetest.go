// Package storetest is the conformance suite every store.Store passes. The
// memory store is the reference: where store.go leaves a detail open, a
// backend behaves as package mem does.
//
// Records come back as they went in, with two allowances: a nil slice and an
// empty one are equal, and times compare after truncation to microseconds,
// as an instant, whatever their location.
package storetest

import (
	"errors"
	"fmt"
	"math"
	"net/netip"
	"slices"
	"strconv"
	"sync"
	"testing"
	"time"

	"github.com/google/go-cmp/cmp"
	"github.com/google/go-cmp/cmp/cmpopts"

	"github.com/danthegoodman1/wirenet/internal/api"
	"github.com/danthegoodman1/wirenet/internal/model"
	"github.com/danthegoodman1/wirenet/internal/store"
)

// SingleThreaded marks a store that serves one transaction at a time and
// must not be used concurrently. Run skips the concurrency tests for it.
type SingleThreaded interface{ SingleThreaded() }

// Run runs the suite. open returns a new, empty store, and each test opens
// its own.
func Run(t *testing.T, open func(t *testing.T) store.Store) {
	for _, c := range cases {
		t.Run(c.name, func(t *testing.T) { c.run(t, open(t)) })
	}
}

var cases = []struct {
	name string
	run  func(*testing.T, store.Store)
}{
	{"NetworkRoundTrip", testNetworkRoundTrip},
	{"NetworkLookups", testNetworkLookups},
	{"NetworkReplaceAndDelete", testNetworkReplaceAndDelete},
	{"ServiceRoundTrip", testServiceRoundTrip},
	{"ServiceLookups", testServiceLookups},
	{"ServiceReplaceAndDelete", testServiceReplaceAndDelete},
	{"InterfaceRoundTrip", testInterfaceRoundTrip},
	{"InterfaceLists", testInterfaceLists},
	{"InterfaceReplaceAndDelete", testInterfaceReplaceAndDelete},
	{"Expired", testExpired},
	{"Undrained", testUndrained},
	{"Ended", testEnded},
	{"Rules", testRules},
	{"EdgeRoundTrip", testEdgeRoundTrip},
	{"EdgesSortByPair", testEdgesSortByPair},
	{"RelayEdges", testRelayEdges},
	{"EdgeReplaceAndDelete", testEdgeReplaceAndDelete},
	{"DormantEdges", testDormantEdges},
	{"Hosts", testHosts},
	{"Relays", testRelays},
	{"Admins", testAdmins},
	{"Released4", testReleased4},
	{"ReleasedPorts", testReleasedPorts},
	{"PortCursor", testPortCursor},
	{"Meta", testMeta},
	{"UniqueNames", testUniqueNames},
	{"MemberHolders", testMemberHolders},
	{"ConflictLeavesTransactionUsable", testConflictLeavesTransactionUsable},
	{"RecordsAreCopies", testRecordsAreCopies},
	{"UpdateReadsItsOwnWrites", testUpdateReadsItsOwnWrites},
	{"FailedUpdateWritesNothing", testFailedUpdateWritesNothing},
	{"ViewReturnsItsError", testViewReturnsItsError},
	{"Bump", testBump},
	{"Touch", testTouch},
	{"ConcurrentIncrementsSerialize", testConcurrentIncrementsSerialize},
	{"ConcurrentBumpsFollowCommitOrder", testConcurrentBumpsFollowCommitOrder},
	{"ConcurrentPutsOfOneName", testConcurrentPutsOfOneName},
}

// t0 is the suite's epoch. Times that queries compare against sit on whole
// seconds from it.
var t0 = time.Date(2031, 2, 3, 4, 5, 6, 0, time.UTC)

func at(sec int) time.Time { return t0.Add(time.Duration(sec) * time.Second) }

// fine is a time with nanoseconds, in a location other than UTC.
var fine = t0.Add(123456789 * time.Nanosecond).In(time.FixedZone("UTC+5", 5*3600))

var equal = cmp.Options{
	cmpopts.EquateEmpty(),
	cmp.Comparer(func(a, b time.Time) bool {
		return a.Truncate(time.Microsecond).Equal(b.Truncate(time.Microsecond))
	}),
	cmp.Comparer(func(a, b netip.Addr) bool { return a == b }),
	cmp.Comparer(func(a, b netip.Prefix) bool { return a == b }),
	cmp.Comparer(func(a, b netip.AddrPort) bool { return a == b }),
}

func same(t *testing.T, what string, got, want any) {
	t.Helper()
	if d := cmp.Diff(want, got, equal); d != "" {
		t.Errorf("%s (-want +got):\n%s", what, d)
	}
}

var errBoom = errors.New("boom")

// update runs fn and fails t if the transaction does not commit.
func update(t *testing.T, s store.Store, fn func(store.Tx) error) store.Change {
	t.Helper()
	ch, err := s.Update(t.Context(), fn)
	if err != nil {
		t.Fatal(err)
	}
	return ch
}

// put writes vs in one transaction.
func put[V any](t *testing.T, s store.Store, write func(store.Tx, V) error, vs ...V) {
	t.Helper()
	update(t, s, func(tx store.Tx) error {
		for _, v := range vs {
			if err := write(tx, v); err != nil {
				return err
			}
		}
		return nil
	})
}

// read returns what fn reads from a snapshot.
func read[V any](t *testing.T, s store.Store, fn func(store.ReadTx) (V, error)) V {
	t.Helper()
	var v V
	if err := s.View(t.Context(), func(tx store.ReadTx) error {
		var err error
		v, err = fn(tx)
		return err
	}); err != nil {
		t.Fatal(err)
	}
	return v
}

// missing checks that a lookup reports store.ErrNotFound.
func missing[V any](t *testing.T, s store.Store, what string, fn func(store.ReadTx) (V, error)) {
	t.Helper()
	err := s.View(t.Context(), func(tx store.ReadTx) error {
		_, err := fn(tx)
		return err
	})
	if !errors.Is(err, store.ErrNotFound) {
		t.Errorf("%s: %v, want ErrNotFound", what, err)
	}
}

func key(b byte) [32]byte {
	var k [32]byte
	for i := range k {
		k[i] = b + byte(i)
	}
	return k
}

func addr(s string) netip.Addr { return netip.MustParseAddr(s) }

func putNetwork(tx store.Tx, n store.Network) error           { return tx.PutNetwork(n) }
func putService(tx store.Tx, v store.Service) error           { return tx.PutService(v) }
func putInterface(tx store.Tx, i store.Interface) error       { return tx.PutInterface(i) }
func putRule(tx store.Tx, r store.Rule) error                 { return tx.PutRule(r) }
func putEdge(tx store.Tx, e store.Edge) error                 { return tx.PutEdge(e) }
func putHost(tx store.Tx, h store.Host) error                 { return tx.PutHost(h) }
func putRelay(tx store.Tx, r store.Relay) error               { return tx.PutRelay(r) }
func putReleased4(tx store.Tx, r store.Released4) error       { return tx.PutReleased4(r) }
func putReleasedPort(tx store.Tx, p store.ReleasedPort) error { return tx.PutReleasedPort(p) }

// Records with every field set, and with every optional field zero.

func fullNetwork(id model.NetworkID, name string) store.Network {
	return store.Network{
		ID: id, Name: name,
		Prefix6: netip.MustParsePrefix("fd12:3456:789a:1::/64"),
		Prefix4: netip.MustParsePrefix("10.20.0.0/16"),
		MTU:     1380,
		Relays:  []model.RelayID{"relay-b", "relay-a"},
		Next6:   math.MaxUint64, Next4: 1<<63 + 7, Revision: 1<<63 + 1,
		Created: fine, Changed: fine.Add(time.Hour),
		Quota: api.Quota{Interfaces: 1000, Services: 50, Rules: 200, Edges: math.MaxInt32},
	}
}

func bareNetwork(id model.NetworkID, name string) store.Network {
	return store.Network{ID: id, Name: name, Created: t0}
}

func fullService(id model.ServiceID, net model.NetworkID, name string) store.Service {
	return store.Service{
		ID: id, Network: net, Name: name, IPv4: true,
		Addr6: addr("fd12:3456:789a:1::105"), Addr4: addr("10.20.0.5"),
		Mode: api.Cutover, Created: fine,
	}
}

func bareService(id model.ServiceID, net model.NetworkID, name string) store.Service {
	return store.Service{ID: id, Network: net, Name: name, Addr6: addr("fd12::1"), Mode: api.Flip, Created: t0}
}

func fullInterface(id model.InterfaceID) store.Interface {
	return store.Interface{
		ID: id, Network: "net-a", Service: "svc-a", Host: "host-a", Kind: api.Device,
		Gateway: "if-gateway", PublicKey: model.Key(key(1)),
		Addr6: addr("fd12:3456:789a:1::106"), Addr4: addr("10.20.0.6"), ListenPort: 65535,
		State: api.Released, Expires: fine.Add(time.Minute), Created: fine, Ended: fine.Add(time.Second),
		Drained: true, Member: "etcd-1",
	}
}

func bareInterface(id model.InterfaceID) store.Interface {
	return store.Interface{
		ID: id, Network: "net-a", Service: "svc-a", Host: "host-a", Kind: api.Workload,
		PublicKey: model.Key(key(2)), Addr6: addr("fd12::2"), ListenPort: 1, State: api.Live,
		Expires: at(30), Created: t0,
	}
}

func fullEdge(net model.NetworkID, a, b model.InterfaceID) store.Edge {
	return store.Edge{
		Network: net, A: a, B: b, SecretAB: model.Secret(key(3)), SecretBA: model.Secret(key(4)),
		Ports: []store.EdgePorts{
			{Relay: "relay-b", Addr: addr("10.0.0.2"), AB: 20001, BA: 20002},
			{Relay: "relay-a", Addr: addr("2001:db8::2"), AB: 65534, BA: 1024},
		},
		Created: fine, Dormant: fine.Add(time.Hour),
	}
}

func bareEdge(net model.NetworkID, a, b model.InterfaceID) store.Edge {
	return store.Edge{Network: net, A: a, B: b, SecretAB: model.Secret(key(5)), SecretBA: model.Secret(key(6)), Created: t0}
}

func fullHost(id model.HostID, name string) store.Host {
	return store.Host{
		ID: id, Name: name, TokenHash: key(7), Endpoint: netip.MustParseAddrPort("[2001:db8::7]:51820"),
		Revision: 1<<63 + 3, Created: fine, Scope: store.Scope{Networks: []model.NetworkID{"net-b", "net-a"}},
	}
}

func bareHost(id model.HostID, name string) store.Host {
	return store.Host{ID: id, Name: name, TokenHash: key(8), Created: t0}
}

func fullAdmin(id model.AdminID, name string) store.Admin {
	return store.Admin{
		ID: id, Name: name, TokenHash: key(13), Created: fine,
		Scope: store.Scope{Networks: []model.NetworkID{"net-b", "net-a"}},
	}
}

func bareAdmin(id model.AdminID, name string) store.Admin {
	return store.Admin{ID: id, Name: name, TokenHash: key(14), Created: t0}
}

func fullRelay(id model.RelayID, name string) store.Relay {
	return store.Relay{
		ID: id, Name: name, TokenHash: key(9),
		Addresses: []api.RelayAddress{
			{Local: addr("10.0.0.9"), Advertised: addr("198.51.100.9")},
			{Local: addr("2001:db8::9"), Advertised: addr("2001:db8:1::9")},
		},
		PortLo: 1024, PortHi: 65534, ProbePort: 1023, Revision: math.MaxUint64, Created: fine,
	}
}

func bareRelay(id model.RelayID, name string) store.Relay {
	return store.Relay{ID: id, Name: name, TokenHash: key(10), Created: t0}
}

func testNetworkRoundTrip(t *testing.T, s store.Store) {
	full, bare := fullNetwork("net-full", "full"), bareNetwork("net-bare", "bare")
	put(t, s, putNetwork, full, bare)
	for _, want := range []store.Network{full, bare} {
		same(t, "Network", read(t, s, func(tx store.ReadTx) (store.Network, error) { return tx.Network(want.ID) }), want)
		same(t, "NetworkByName", read(t, s, func(tx store.ReadTx) (store.Network, error) { return tx.NetworkByName(want.Name) }), want)
	}
	same(t, "Networks", read(t, s, store.ReadTx.Networks), []store.Network{bare, full})
}

func testNetworkLookups(t *testing.T, s store.Store) {
	missing(t, s, "Network", func(tx store.ReadTx) (store.Network, error) { return tx.Network("net-none") })
	missing(t, s, "NetworkByName", func(tx store.ReadTx) (store.Network, error) { return tx.NetworkByName("none") })
	same(t, "Networks of an empty store", read(t, s, store.ReadTx.Networks), []store.Network(nil))
	// Identifiers sort as Go strings: by byte, case and punctuation
	// included.
	var want []store.Network
	for i, id := range []model.NetworkID{"net_c", "net-a-1", "net-a", "net-B"} {
		want = append(want, bareNetwork(id, fmt.Sprintf("n%d", i)))
	}
	put(t, s, putNetwork, want...)
	slices.SortFunc(want, func(a, b store.Network) int { return compare(a.ID, b.ID) })
	same(t, "Networks", read(t, s, store.ReadTx.Networks), want)
	missing(t, s, "Network of another case", func(tx store.ReadTx) (store.Network, error) { return tx.Network("net-b") })
}

func compare[T ~string](a, b T) int {
	switch {
	case a < b:
		return -1
	case a > b:
		return 1
	}
	return 0
}

func testNetworkReplaceAndDelete(t *testing.T, s store.Store) {
	n := bareNetwork("net-a", "old")
	put(t, s, putNetwork, n, bareNetwork("net-b", "b"))
	n = fullNetwork("net-a", "new")
	put(t, s, putNetwork, n)
	same(t, "replaced Network", read(t, s, func(tx store.ReadTx) (store.Network, error) { return tx.Network("net-a") }), n)
	missing(t, s, "NetworkByName of the old name", func(tx store.ReadTx) (store.Network, error) { return tx.NetworkByName("old") })
	update(t, s, func(tx store.Tx) error { return tx.DeleteNetwork("net-a") })
	missing(t, s, "deleted Network", func(tx store.ReadTx) (store.Network, error) { return tx.Network("net-a") })
	missing(t, s, "deleted NetworkByName", func(tx store.ReadTx) (store.Network, error) { return tx.NetworkByName("new") })
	update(t, s, func(tx store.Tx) error { return tx.DeleteNetwork("net-none") })
	same(t, "Networks", read(t, s, store.ReadTx.Networks), []store.Network{bareNetwork("net-b", "b")})
}

func testServiceRoundTrip(t *testing.T, s store.Store) {
	full, bare := fullService("svc-full", "net-a", "full"), bareService("svc-bare", "net-a", "bare")
	put(t, s, putService, full, bare)
	for _, want := range []store.Service{full, bare} {
		same(t, "Service", read(t, s, func(tx store.ReadTx) (store.Service, error) { return tx.Service(want.ID) }), want)
		same(t, "ServiceByName", read(t, s, func(tx store.ReadTx) (store.Service, error) {
			return tx.ServiceByName(want.Network, want.Name)
		}), want)
	}
	same(t, "Services", read(t, s, func(tx store.ReadTx) ([]store.Service, error) { return tx.Services("net-a") }), []store.Service{bare, full})
}

func testServiceLookups(t *testing.T, s store.Store) {
	a3, a1, b2 := bareService("svc-3", "net-a", "web"), bareService("svc-1", "net-a", "db"), bareService("svc-2", "net-b", "web")
	put(t, s, putService, a3, a1, b2)
	same(t, "Services of net-a", read(t, s, func(tx store.ReadTx) ([]store.Service, error) { return tx.Services("net-a") }), []store.Service{a1, a3})
	same(t, "Services of net-c", read(t, s, func(tx store.ReadTx) ([]store.Service, error) { return tx.Services("net-c") }), []store.Service(nil))
	same(t, "ServiceByName in net-b", read(t, s, func(tx store.ReadTx) (store.Service, error) { return tx.ServiceByName("net-b", "web") }), b2)
	missing(t, s, "ServiceByName in another network", func(tx store.ReadTx) (store.Service, error) { return tx.ServiceByName("net-b", "db") })
	missing(t, s, "Service", func(tx store.ReadTx) (store.Service, error) { return tx.Service("svc-none") })
}

func testServiceReplaceAndDelete(t *testing.T, s store.Store) {
	put(t, s, putService, bareService("svc-a", "net-a", "old"))
	v := fullService("svc-a", "net-a", "new")
	put(t, s, putService, v)
	same(t, "replaced Service", read(t, s, func(tx store.ReadTx) (store.Service, error) { return tx.Service("svc-a") }), v)
	missing(t, s, "ServiceByName of the old name", func(tx store.ReadTx) (store.Service, error) { return tx.ServiceByName("net-a", "old") })
	update(t, s, func(tx store.Tx) error { return tx.DeleteService("svc-a") })
	missing(t, s, "deleted Service", func(tx store.ReadTx) (store.Service, error) { return tx.Service("svc-a") })
	update(t, s, func(tx store.Tx) error { return tx.DeleteService("svc-none") })
}

func testInterfaceRoundTrip(t *testing.T, s store.Store) {
	full, bare := fullInterface("if-full"), bareInterface("if-bare")
	put(t, s, putInterface, full, bare)
	for _, want := range []store.Interface{full, bare} {
		same(t, "Interface", read(t, s, func(tx store.ReadTx) (store.Interface, error) { return tx.Interface(want.ID) }), want)
	}
	missing(t, s, "Interface", func(tx store.ReadTx) (store.Interface, error) { return tx.Interface("if-none") })
}

func testInterfaceLists(t *testing.T, s store.Store) {
	mk := func(id model.InterfaceID, net model.NetworkID, host model.HostID, state api.LeaseState) store.Interface {
		i := bareInterface(id)
		i.Network, i.Host, i.State = net, host, state
		return i
	}
	all := []store.Interface{
		mk("if_c", "net-a", "host-1", api.Live),
		mk("if-a-1", "net-a", "host-2", api.Released),
		mk("if-a", "net-b", "host-1", api.Revoked),
		mk("if-B", "net-a", "host-1", api.Revoked),
		mk("if-d", "net-b", "host-2", api.Live),
	}
	put(t, s, putInterface, all...)
	pick := func(keep func(store.Interface) bool) []store.Interface {
		out := slices.DeleteFunc(slices.Clone(all), func(i store.Interface) bool { return !keep(i) })
		slices.SortFunc(out, func(a, b store.Interface) int { return compare(a.ID, b.ID) })
		return out
	}
	for _, net := range []model.NetworkID{"net-a", "net-b", "net-c"} {
		same(t, "Interfaces of "+string(net), read(t, s, func(tx store.ReadTx) ([]store.Interface, error) { return tx.Interfaces(net) }),
			pick(func(i store.Interface) bool { return i.Network == net }))
	}
	for _, host := range []model.HostID{"host-1", "host-2", "host-3"} {
		same(t, "HostInterfaces of "+string(host), read(t, s, func(tx store.ReadTx) ([]store.Interface, error) { return tx.HostInterfaces(host) }),
			pick(func(i store.Interface) bool { return i.Host == host }))
	}
}

func testInterfaceReplaceAndDelete(t *testing.T, s store.Store) {
	put(t, s, putInterface, bareInterface("if-a"))
	i := fullInterface("if-a")
	put(t, s, putInterface, i)
	same(t, "replaced Interface", read(t, s, func(tx store.ReadTx) (store.Interface, error) { return tx.Interface("if-a") }), i)
	// A replaced interface leaves the lists it no longer belongs to.
	i.Network, i.Host = "net-b", "host-b"
	put(t, s, putInterface, i)
	same(t, "Interfaces of the old network", read(t, s, func(tx store.ReadTx) ([]store.Interface, error) { return tx.Interfaces("net-a") }), []store.Interface(nil))
	same(t, "HostInterfaces of the old host", read(t, s, func(tx store.ReadTx) ([]store.Interface, error) { return tx.HostInterfaces("host-a") }), []store.Interface(nil))
	same(t, "Interfaces of the new network", read(t, s, func(tx store.ReadTx) ([]store.Interface, error) { return tx.Interfaces("net-b") }), []store.Interface{i})
	update(t, s, func(tx store.Tx) error { return tx.DeleteInterface("if-a") })
	missing(t, s, "deleted Interface", func(tx store.ReadTx) (store.Interface, error) { return tx.Interface("if-a") })
	same(t, "HostInterfaces after delete", read(t, s, func(tx store.ReadTx) ([]store.Interface, error) { return tx.HostInterfaces("host-b") }), []store.Interface(nil))
	update(t, s, func(tx store.Tx) error { return tx.DeleteInterface("if-none") })
}

// lease makes an interface in a state, with an expiry and an end.
func lease(id model.InterfaceID, state api.LeaseState, drained bool, expires, ended time.Time) store.Interface {
	i := bareInterface(id)
	i.State, i.Drained, i.Expires, i.Ended = state, drained, expires, ended
	return i
}

func ids(is []store.Interface) []model.InterfaceID {
	var out []model.InterfaceID
	for _, i := range is {
		out = append(out, i.ID)
	}
	return out
}

func testExpired(t *testing.T, s store.Store) {
	put(t, s, putInterface,
		lease("if-a", api.Live, false, at(50), time.Time{}),
		lease("if-b", api.Live, false, at(10), time.Time{}),
		lease("if-c", api.Live, false, at(99), time.Time{}),
		lease("if-d", api.Live, false, at(100), time.Time{}),
		lease("if-e", api.Live, false, at(200), time.Time{}),
		lease("if-f", api.Released, false, at(5), at(6)),
		lease("if-g", api.Revoked, true, at(1), at(2)),
	)
	expired := func(before time.Time, limit int) []model.InterfaceID {
		return ids(read(t, s, func(tx store.ReadTx) ([]store.Interface, error) { return tx.Expired(before, limit) }))
	}
	same(t, "Expired", expired(at(100), 10), []model.InterfaceID{"if-b", "if-a", "if-c"})
	same(t, "Expired up to 2", expired(at(100), 2), []model.InterfaceID{"if-b", "if-a"})
	same(t, "Expired at the first expiry", expired(at(10), 10), []model.InterfaceID(nil))
	full := read(t, s, func(tx store.ReadTx) ([]store.Interface, error) { return tx.Expired(at(11), 1) })
	same(t, "Expired returns whole records", full, []store.Interface{lease("if-b", api.Live, false, at(10), time.Time{})})
}

func testUndrained(t *testing.T, s store.Store) {
	put(t, s, putInterface,
		lease("if-a", api.Released, false, at(1), at(30)),
		lease("if-b", api.Released, false, at(1), at(20)),
		lease("if-c", api.Released, true, at(1), at(10)),
		lease("if-d", api.Revoked, false, at(1), at(5)),
		lease("if-e", api.Live, false, at(1), time.Time{}),
		lease("if-f", api.Released, false, at(1), at(100)),
		lease("if-g", api.Released, false, at(1), at(25)),
	)
	undrained := func(before time.Time, limit int) []model.InterfaceID {
		return ids(read(t, s, func(tx store.ReadTx) ([]store.Interface, error) { return tx.Undrained(before, limit) }))
	}
	same(t, "Undrained", undrained(at(100), 10), []model.InterfaceID{"if-b", "if-g", "if-a"})
	same(t, "Undrained up to 1", undrained(at(100), 1), []model.InterfaceID{"if-b"})
}

func testEnded(t *testing.T, s store.Store) {
	put(t, s, putInterface,
		lease("if-a", api.Revoked, true, at(1), at(40)),
		lease("if-b", api.Released, true, at(1), at(30)),
		lease("if-c", api.Released, false, at(1), at(5)),
		lease("if-d", api.Live, true, at(1), at(1)),
		lease("if-e", api.Revoked, true, at(1), at(150)),
		lease("if-f", api.Revoked, true, at(1), at(35)),
	)
	ended := func(before time.Time, limit int) []model.InterfaceID {
		return ids(read(t, s, func(tx store.ReadTx) ([]store.Interface, error) { return tx.Ended(before, limit) }))
	}
	same(t, "Ended", ended(at(100), 10), []model.InterfaceID{"if-b", "if-f", "if-a"})
	same(t, "Ended up to 2", ended(at(100), 2), []model.InterfaceID{"if-b", "if-f"})
}

func testRules(t *testing.T, s store.Store) {
	full := store.Rule{
		ID: "rule-b", Network: "net-a", From: "svc-a", To: "svc-b", Proto: model.TCP,
		Ports: model.PortRange{Lo: 5432, Hi: 65535}, Created: fine,
	}
	internet := store.Rule{ID: "rule-a", Network: "net-a", From: "svc-a", Proto: model.AnyProto, Created: t0}
	other := store.Rule{ID: "rule-c", Network: "net-b", From: "svc-c", To: "svc-c", Proto: model.UDP, Ports: model.PortRange{Lo: 53, Hi: 53}, Created: t0}
	denied := store.Rule{ID: "rule-d", Network: "net-b", From: model.AnyService, To: "svc-c", Proto: model.TCP, Ports: model.PortRange{Lo: 22, Hi: 22}, Created: t0, Deny: true}
	put(t, s, putRule, full, internet, other, denied)
	for _, want := range []store.Rule{full, internet, other, denied} {
		same(t, "Rule", read(t, s, func(tx store.ReadTx) (store.Rule, error) { return tx.Rule(want.ID) }), want)
	}
	same(t, "Rules", read(t, s, func(tx store.ReadTx) ([]store.Rule, error) { return tx.Rules("net-a") }), []store.Rule{internet, full})
	missing(t, s, "Rule", func(tx store.ReadTx) (store.Rule, error) { return tx.Rule("rule-none") })
	same(t, "Rules", read(t, s, func(tx store.ReadTx) ([]store.Rule, error) { return tx.Rules("net-b") }), []store.Rule{other, denied})
	full.Ports, full.Deny = model.PortRange{Lo: 1, Hi: 2}, true
	put(t, s, putRule, full)
	same(t, "replaced Rule", read(t, s, func(tx store.ReadTx) (store.Rule, error) { return tx.Rule("rule-b") }), full)
	update(t, s, func(tx store.Tx) error { return tx.DeleteRule("rule-a") })
	update(t, s, func(tx store.Tx) error { return tx.DeleteRule("rule-none") })
	missing(t, s, "deleted Rule", func(tx store.ReadTx) (store.Rule, error) { return tx.Rule("rule-a") })
	same(t, "Rules after delete", read(t, s, func(tx store.ReadTx) ([]store.Rule, error) { return tx.Rules("net-a") }), []store.Rule{full})
}

func edges(t *testing.T, s store.Store, net model.NetworkID) []store.Edge {
	t.Helper()
	return read(t, s, func(tx store.ReadTx) ([]store.Edge, error) { return tx.Edges(net) })
}

func testEdgeRoundTrip(t *testing.T, s store.Store) {
	full, bare := fullEdge("net-a", "if-a", "if-b"), bareEdge("net-a", "if-a", "if-c")
	put(t, s, putEdge, full, bare)
	same(t, "Edges", edges(t, s, "net-a"), []store.Edge{full, bare})
}

func testEdgesSortByPair(t *testing.T, s store.Store) {
	bc, ac, ab, cd := bareEdge("net-a", "if-b", "if-c"), bareEdge("net-a", "if-a", "if-c"), bareEdge("net-a", "if-a", "if-b"), bareEdge("net-a", "if-c", "if-d")
	put(t, s, putEdge, bc, ac, bareEdge("net-b", "if-a", "if-a1"), ab, cd)
	same(t, "Edges of net-a", edges(t, s, "net-a"), []store.Edge{ab, ac, bc, cd})
	same(t, "Edges of net-c", edges(t, s, "net-c"), []store.Edge(nil))
}

func onRelays(e store.Edge, relays ...model.RelayID) store.Edge {
	e.Ports = nil
	for i, r := range relays {
		e.Ports = append(e.Ports, store.EdgePorts{Relay: r, Addr: addr("10.0.0.1"), AB: uint16(30000 + 2*i), BA: uint16(30001 + 2*i)})
	}
	return e
}

func testRelayEdges(t *testing.T, s store.Store) {
	xy := onRelays(bareEdge("net-b", "if-x", "if-y"), "relay-a")
	bc := onRelays(bareEdge("net-a", "if-b", "if-c"), "relay-b", "relay-a")
	ac := onRelays(bareEdge("net-a", "if-a", "if-c"), "relay-b")
	ab := onRelays(bareEdge("net-a", "if-a", "if-b"), "relay-a")
	cd := bareEdge("net-a", "if-c", "if-d")
	de := onRelays(bareEdge("net-a", "if-d", "if-e"), "relay-ab")
	put(t, s, putEdge, xy, bc, ac, ab, cd, de)
	relayEdges := func(r model.RelayID) []store.Edge {
		return read(t, s, func(tx store.ReadTx) ([]store.Edge, error) { return tx.RelayEdges(r) })
	}
	same(t, "RelayEdges of relay-a", relayEdges("relay-a"), []store.Edge{ab, bc, xy})
	same(t, "RelayEdges of relay-b", relayEdges("relay-b"), []store.Edge{ac, bc})
	same(t, "RelayEdges of relay-z", relayEdges("relay-z"), []store.Edge(nil))
	// An edge that moves off a relay leaves its list.
	put(t, s, putEdge, onRelays(bc, "relay-b"))
	same(t, "RelayEdges of relay-a after a move", relayEdges("relay-a"), []store.Edge{ab, xy})
}

func testEdgeReplaceAndDelete(t *testing.T, s store.Store) {
	put(t, s, putEdge, bareEdge("net-a", "if-a", "if-b"), bareEdge("net-b", "if-a", "if-b"))
	e := fullEdge("net-a", "if-a", "if-b")
	put(t, s, putEdge, e)
	same(t, "replaced Edges", edges(t, s, "net-a"), []store.Edge{e})
	e.Dormant = time.Time{}
	put(t, s, putEdge, e)
	same(t, "Edges after waking", edges(t, s, "net-a"), []store.Edge{e})
	update(t, s, func(tx store.Tx) error { return tx.DeleteEdge("net-a", "if-a", "if-b") })
	update(t, s, func(tx store.Tx) error { return tx.DeleteEdge("net-a", "if-a", "if-none") })
	same(t, "Edges after delete", edges(t, s, "net-a"), []store.Edge(nil))
	same(t, "Edges of the other network", edges(t, s, "net-b"), []store.Edge{bareEdge("net-b", "if-a", "if-b")})
}

func testDormantEdges(t *testing.T, s store.Store) {
	dormant := func(e store.Edge, since time.Time) store.Edge { e.Dormant = since; return e }
	ab := dormant(bareEdge("net-a", "if-a", "if-b"), at(30))
	ac := dormant(bareEdge("net-a", "if-a", "if-c"), at(10))
	cd := dormant(bareEdge("net-a", "if-c", "if-d"), at(100))
	other := dormant(bareEdge("net-b", "if-a", "if-b"), at(20))
	put(t, s, putEdge, ab, ac, bareEdge("net-a", "if-b", "if-c"), cd, other)
	dormantEdges := func(before time.Time, limit int) []store.Edge {
		return read(t, s, func(tx store.ReadTx) ([]store.Edge, error) { return tx.DormantEdges(before, limit) })
	}
	same(t, "DormantEdges", dormantEdges(at(100), 10), []store.Edge{ac, other, ab})
	same(t, "DormantEdges up to 2", dormantEdges(at(100), 2), []store.Edge{ac, other})
	same(t, "DormantEdges before any", dormantEdges(at(10), 10), []store.Edge(nil))
}

func testHosts(t *testing.T, s store.Store) {
	full, bare := fullHost("host-full", "full"), bareHost("host-bare", "bare")
	global := bareHost("host-global", "global")
	global.TokenHash, global.Scope = key(15), store.Scope{Global: true}
	put(t, s, putHost, full, bare, global)
	same(t, "Hosts", read(t, s, store.ReadTx.Hosts), []store.Host{bare, full, global})
	for _, want := range []store.Host{full, bare, global} {
		same(t, "Host", read(t, s, func(tx store.ReadTx) (store.Host, error) { return tx.Host(want.ID) }), want)
		same(t, "HostByName", read(t, s, func(tx store.ReadTx) (store.Host, error) { return tx.HostByName(want.Name) }), want)
		same(t, "HostByToken", read(t, s, func(tx store.ReadTx) (store.Host, error) { return tx.HostByToken(want.TokenHash) }), want)
	}
	missing(t, s, "Host", func(tx store.ReadTx) (store.Host, error) { return tx.Host("host-none") })
	missing(t, s, "HostByName", func(tx store.ReadTx) (store.Host, error) { return tx.HostByName("none") })
	missing(t, s, "HostByToken", func(tx store.ReadTx) (store.Host, error) { return tx.HostByToken(key(99)) })
	full.Name, full.TokenHash, full.Endpoint = "renamed", key(11), netip.AddrPort{}
	put(t, s, putHost, full)
	same(t, "replaced Host", read(t, s, func(tx store.ReadTx) (store.Host, error) { return tx.HostByToken(key(11)) }), full)
	missing(t, s, "HostByToken of the old token", func(tx store.ReadTx) (store.Host, error) { return tx.HostByToken(key(7)) })
	missing(t, s, "HostByName of the old name", func(tx store.ReadTx) (store.Host, error) { return tx.HostByName("full") })
	update(t, s, func(tx store.Tx) error { return errors.Join(tx.DeleteHost("host-full"), tx.DeleteHost("host-none")) })
	missing(t, s, "deleted Host", func(tx store.ReadTx) (store.Host, error) { return tx.Host("host-full") })
	missing(t, s, "deleted HostByName", func(tx store.ReadTx) (store.Host, error) { return tx.HostByName("renamed") })
	missing(t, s, "deleted HostByToken", func(tx store.ReadTx) (store.Host, error) { return tx.HostByToken(key(11)) })
	same(t, "the other Host", read(t, s, func(tx store.ReadTx) (store.Host, error) { return tx.HostByToken(bare.TokenHash) }), bare)
	same(t, "Hosts after a delete", read(t, s, store.ReadTx.Hosts), []store.Host{bare, global})
}

func putAdmin(tx store.Tx, a store.Admin) error { return tx.PutAdmin(a) }

func testAdmins(t *testing.T, s store.Store) {
	full, bare := fullAdmin("admin-full", "full"), bareAdmin("admin-bare", "bare")
	put(t, s, putAdmin, full, bare)
	for _, want := range []store.Admin{full, bare} {
		same(t, "Admin", read(t, s, func(tx store.ReadTx) (store.Admin, error) { return tx.Admin(want.ID) }), want)
		same(t, "AdminByName", read(t, s, func(tx store.ReadTx) (store.Admin, error) { return tx.AdminByName(want.Name) }), want)
		same(t, "AdminByToken", read(t, s, func(tx store.ReadTx) (store.Admin, error) { return tx.AdminByToken(want.TokenHash) }), want)
	}
	same(t, "Admins", read(t, s, store.ReadTx.Admins), []store.Admin{bare, full})
	missing(t, s, "Admin", func(tx store.ReadTx) (store.Admin, error) { return tx.Admin("admin-none") })
	missing(t, s, "AdminByName", func(tx store.ReadTx) (store.Admin, error) { return tx.AdminByName("none") })
	missing(t, s, "AdminByToken", func(tx store.ReadTx) (store.Admin, error) { return tx.AdminByToken(key(99)) })
	full.Name, full.TokenHash, full.Scope.Networks = "renamed", key(16), full.Scope.Networks[1:]
	put(t, s, putAdmin, full)
	same(t, "replaced Admin", read(t, s, func(tx store.ReadTx) (store.Admin, error) { return tx.AdminByToken(key(16)) }), full)
	missing(t, s, "AdminByToken of the old token", func(tx store.ReadTx) (store.Admin, error) { return tx.AdminByToken(key(13)) })
	missing(t, s, "AdminByName of the old name", func(tx store.ReadTx) (store.Admin, error) { return tx.AdminByName("full") })
	update(t, s, func(tx store.Tx) error {
		return errors.Join(tx.DeleteAdmin("admin-full"), tx.DeleteAdmin("admin-none"))
	})
	missing(t, s, "deleted Admin", func(tx store.ReadTx) (store.Admin, error) { return tx.Admin("admin-full") })
	missing(t, s, "deleted AdminByToken", func(tx store.ReadTx) (store.Admin, error) { return tx.AdminByToken(key(16)) })
	same(t, "Admins after a delete", read(t, s, store.ReadTx.Admins), []store.Admin{bare})
}

func testRelays(t *testing.T, s store.Store) {
	full, bare := fullRelay("relay-full", "full"), bareRelay("relay-bare", "bare")
	put(t, s, putRelay, full, bare)
	for _, want := range []store.Relay{full, bare} {
		same(t, "Relay", read(t, s, func(tx store.ReadTx) (store.Relay, error) { return tx.Relay(want.ID) }), want)
		same(t, "RelayByName", read(t, s, func(tx store.ReadTx) (store.Relay, error) { return tx.RelayByName(want.Name) }), want)
		same(t, "RelayByToken", read(t, s, func(tx store.ReadTx) (store.Relay, error) { return tx.RelayByToken(want.TokenHash) }), want)
	}
	same(t, "Relays", read(t, s, store.ReadTx.Relays), []store.Relay{bare, full})
	missing(t, s, "Relay", func(tx store.ReadTx) (store.Relay, error) { return tx.Relay("relay-none") })
	missing(t, s, "RelayByName", func(tx store.ReadTx) (store.Relay, error) { return tx.RelayByName("none") })
	missing(t, s, "RelayByToken", func(tx store.ReadTx) (store.Relay, error) { return tx.RelayByToken(key(99)) })
	full.Name, full.TokenHash, full.Addresses = "renamed", key(12), full.Addresses[1:]
	put(t, s, putRelay, full)
	same(t, "replaced Relay", read(t, s, func(tx store.ReadTx) (store.Relay, error) { return tx.RelayByToken(key(12)) }), full)
	missing(t, s, "RelayByToken of the old token", func(tx store.ReadTx) (store.Relay, error) { return tx.RelayByToken(key(9)) })

	// A deleted relay takes its port cursors and released ports with it,
	// and leaves the other relay's.
	kept := store.ReleasedPort{Relay: "relay-bare", Addr: addr("10.0.0.9"), Port: 20001, At: at(1)}
	update(t, s, func(tx store.Tx) error {
		return errors.Join(
			tx.SetPortCursor("relay-full", addr("10.0.0.9"), 20005), tx.SetPortCursor("relay-full", addr("2001:db8::9"), 20007),
			tx.SetPortCursor("relay-bare", addr("10.0.0.9"), 20002),
			tx.PutReleasedPort(store.ReleasedPort{Relay: "relay-full", Addr: addr("10.0.0.9"), Port: 20001, At: at(1)}),
			tx.PutReleasedPort(store.ReleasedPort{Relay: "relay-full", Addr: addr("2001:db8::9"), Port: 20003, At: at(1)}),
			tx.PutReleasedPort(kept),
		)
	})
	update(t, s, func(tx store.Tx) error {
		return errors.Join(tx.DeleteRelay("relay-full"), tx.DeleteRelay("relay-none"))
	})
	missing(t, s, "deleted Relay", func(tx store.ReadTx) (store.Relay, error) { return tx.Relay("relay-full") })
	missing(t, s, "deleted RelayByToken", func(tx store.ReadTx) (store.Relay, error) { return tx.RelayByToken(key(12)) })
	same(t, "Relays after a delete", read(t, s, store.ReadTx.Relays), []store.Relay{bare})
	for _, a := range []string{"10.0.0.9", "2001:db8::9"} {
		same(t, "deleted relay's PortCursor on "+a, read(t, s, func(tx store.ReadTx) (uint16, error) { return tx.PortCursor("relay-full", addr(a)) }), uint16(0))
		same(t, "deleted relay's ReleasedPorts on "+a, read(t, s, func(tx store.ReadTx) ([]store.ReleasedPort, error) {
			return tx.ReleasedPorts("relay-full", addr(a), at(100), 0)
		}), []store.ReleasedPort(nil))
	}
	same(t, "the other relay's PortCursor", read(t, s, func(tx store.ReadTx) (uint16, error) { return tx.PortCursor("relay-bare", addr("10.0.0.9")) }), uint16(20002))
	same(t, "the other relay's ReleasedPorts", read(t, s, func(tx store.ReadTx) ([]store.ReleasedPort, error) {
		return tx.ReleasedPorts("relay-bare", addr("10.0.0.9"), at(100), 0)
	}), []store.ReleasedPort{kept})
}

func testReleased4(t *testing.T, s store.Store) {
	r := func(net model.NetworkID, a string, when time.Time) store.Released4 {
		return store.Released4{Network: net, Addr: addr(a), At: when}
	}
	put(t, s, putReleased4,
		r("net-a", "10.0.0.5", at(30)),
		r("net-a", "10.0.0.3", at(10)),
		r("net-a", "10.0.0.4", at(20)),
		r("net-a", "10.0.0.9", at(100)),
		r("net-a", "10.0.0.7", time.Time{}),
		r("net-b", "10.0.0.1", at(1)),
	)
	released := func(limit int) []store.Released4 {
		return read(t, s, func(tx store.ReadTx) ([]store.Released4, error) { return tx.Released4("net-a", at(100), limit) })
	}
	same(t, "Released4", released(10), []store.Released4{
		r("net-a", "10.0.0.7", time.Time{}), r("net-a", "10.0.0.3", at(10)), r("net-a", "10.0.0.4", at(20)), r("net-a", "10.0.0.5", at(30)),
	})
	same(t, "Released4 up to 2", released(2), []store.Released4{r("net-a", "10.0.0.7", time.Time{}), r("net-a", "10.0.0.3", at(10))})
	same(t, "Released4 with no limit", released(0), released(10))
	put(t, s, putReleased4, r("net-a", "10.0.0.3", at(50)))
	update(t, s, func(tx store.Tx) error {
		if err := tx.DeleteReleased4("net-a", addr("10.0.0.4")); err != nil {
			return err
		}
		return tx.DeleteReleased4("net-a", addr("10.0.0.99"))
	})
	same(t, "Released4 after a replace and a delete", released(10), []store.Released4{
		r("net-a", "10.0.0.7", time.Time{}), r("net-a", "10.0.0.5", at(30)), r("net-a", "10.0.0.3", at(50)),
	})
	put(t, s, putReleased4, r("net-c", "10.0.0.1", fine))
	same(t, "Released4 with a fine time", read(t, s, func(tx store.ReadTx) ([]store.Released4, error) {
		return tx.Released4("net-c", fine.Add(time.Microsecond), 10)
	}), []store.Released4{r("net-c", "10.0.0.1", fine)})
}

func testReleasedPorts(t *testing.T, s store.Store) {
	p := func(relay model.RelayID, a string, port uint16, when time.Time) store.ReleasedPort {
		return store.ReleasedPort{Relay: relay, Addr: addr(a), Port: port, At: when}
	}
	put(t, s, putReleasedPort,
		p("relay-a", "10.0.0.1", 20005, at(30)),
		p("relay-a", "10.0.0.1", 20003, at(10)),
		// A zero time frees a port at once.
		p("relay-a", "10.0.0.1", 20004, time.Time{}),
		p("relay-a", "10.0.0.1", 20009, at(100)),
		p("relay-a", "10.0.0.2", 20001, at(1)),
		p("relay-b", "10.0.0.1", 20002, at(1)),
		p("relay-a", "2001:db8::1", 20007, at(2)),
	)
	released := func(limit int) []store.ReleasedPort {
		return read(t, s, func(tx store.ReadTx) ([]store.ReleasedPort, error) {
			return tx.ReleasedPorts("relay-a", addr("10.0.0.1"), at(100), limit)
		})
	}
	same(t, "ReleasedPorts", released(10), []store.ReleasedPort{
		p("relay-a", "10.0.0.1", 20004, time.Time{}), p("relay-a", "10.0.0.1", 20003, at(10)), p("relay-a", "10.0.0.1", 20005, at(30)),
	})
	same(t, "ReleasedPorts up to 1", released(1), []store.ReleasedPort{p("relay-a", "10.0.0.1", 20004, time.Time{})})
	same(t, "ReleasedPorts with no limit", released(0), released(10))
	same(t, "ReleasedPorts on an IPv6 address", read(t, s, func(tx store.ReadTx) ([]store.ReleasedPort, error) {
		return tx.ReleasedPorts("relay-a", addr("2001:db8::1"), at(100), 10)
	}), []store.ReleasedPort{p("relay-a", "2001:db8::1", 20007, at(2))})
	put(t, s, putReleasedPort, p("relay-a", "10.0.0.1", 20004, at(60)))
	update(t, s, func(tx store.Tx) error {
		if err := tx.DeleteReleasedPort("relay-a", addr("10.0.0.1"), 20003); err != nil {
			return err
		}
		return tx.DeleteReleasedPort("relay-a", addr("10.0.0.1"), 1)
	})
	same(t, "ReleasedPorts after a replace and a delete", released(10), []store.ReleasedPort{
		p("relay-a", "10.0.0.1", 20005, at(30)), p("relay-a", "10.0.0.1", 20004, at(60)),
	})
}

func testPortCursor(t *testing.T, s store.Store) {
	cursor := func(relay model.RelayID, a string) uint16 {
		return read(t, s, func(tx store.ReadTx) (uint16, error) { return tx.PortCursor(relay, addr(a)) })
	}
	if c := cursor("relay-a", "10.0.0.1"); c != 0 {
		t.Fatalf("cursor %d before any allocation", c)
	}
	update(t, s, func(tx store.Tx) error { return tx.SetPortCursor("relay-a", addr("10.0.0.1"), 20010) })
	update(t, s, func(tx store.Tx) error { return tx.SetPortCursor("relay-a", addr("2001:db8::1"), 65535) })
	update(t, s, func(tx store.Tx) error { return tx.SetPortCursor("relay-a", addr("10.0.0.1"), 20011) })
	for _, c := range []struct {
		relay model.RelayID
		addr  string
		want  uint16
	}{
		{"relay-a", "10.0.0.1", 20011},
		{"relay-a", "2001:db8::1", 65535},
		{"relay-a", "10.0.0.2", 0},
		{"relay-b", "10.0.0.1", 0},
	} {
		if got := cursor(c.relay, c.addr); got != c.want {
			t.Errorf("cursor of %s %s is %d, want %d", c.relay, c.addr, got, c.want)
		}
	}
}

type metaValue struct {
	Value string
	OK    bool
}

func meta(t *testing.T, s store.Store, k string) metaValue {
	t.Helper()
	return read(t, s, func(tx store.ReadTx) (metaValue, error) {
		v, ok, err := tx.Meta(k)
		return metaValue{v, ok}, err
	})
}

func testMeta(t *testing.T, s store.Store) {
	same(t, "absent Meta", meta(t, s, "k"), metaValue{})
	update(t, s, func(tx store.Tx) error { return tx.SetMeta("k", "v") })
	same(t, "Meta", meta(t, s, "k"), metaValue{"v", true})
	update(t, s, func(tx store.Tx) error { return tx.SetMeta("k", "") })
	same(t, "empty Meta", meta(t, s, "k"), metaValue{"", true})
	same(t, "another key", meta(t, s, "K"), metaValue{})
}

// conflicts checks that put fails with store.ErrConflict, and that the
// failed transaction wrote nothing.
func conflicts(t *testing.T, s store.Store, what string, put func(store.Tx) error) {
	t.Helper()
	ch, err := s.Update(t.Context(), put)
	if !errors.Is(err, store.ErrConflict) {
		t.Errorf("%s: %v, want ErrConflict", what, err)
	}
	if !ch.Empty() || ch.Revision != 0 {
		t.Errorf("%s: a failed update returned %+v", what, ch)
	}
}

func testUniqueNames(t *testing.T, s store.Store) {
	put(t, s, putNetwork, bareNetwork("net-1", "shop"))
	conflicts(t, s, "a second network named shop", func(tx store.Tx) error { return tx.PutNetwork(bareNetwork("net-2", "shop")) })
	missing(t, s, "the conflicting network", func(tx store.ReadTx) (store.Network, error) { return tx.Network("net-2") })
	put(t, s, putNetwork, fullNetwork("net-1", "shop"))

	put(t, s, putHost, bareHost("host-1", "h"))
	conflicts(t, s, "a second host named h", func(tx store.Tx) error { return tx.PutHost(bareHost("host-2", "h")) })
	missing(t, s, "the conflicting host", func(tx store.ReadTx) (store.Host, error) { return tx.Host("host-2") })
	put(t, s, putHost, fullHost("host-1", "h"))

	put(t, s, putRelay, bareRelay("relay-1", "r"))
	conflicts(t, s, "a second relay named r", func(tx store.Tx) error { return tx.PutRelay(bareRelay("relay-2", "r")) })
	missing(t, s, "the conflicting relay", func(tx store.ReadTx) (store.Relay, error) { return tx.Relay("relay-2") })
	put(t, s, putRelay, fullRelay("relay-1", "r"))

	put(t, s, putAdmin, bareAdmin("admin-1", "a"))
	conflicts(t, s, "a second admin named a", func(tx store.Tx) error { return tx.PutAdmin(bareAdmin("admin-2", "a")) })
	missing(t, s, "the conflicting admin", func(tx store.ReadTx) (store.Admin, error) { return tx.Admin("admin-2") })
	put(t, s, putAdmin, fullAdmin("admin-1", "a"))

	put(t, s, putService, bareService("svc-1", "net-1", "web"))
	conflicts(t, s, "a second service named web in net-1", func(tx store.Tx) error {
		return tx.PutService(bareService("svc-2", "net-1", "web"))
	})
	missing(t, s, "the conflicting service", func(tx store.ReadTx) (store.Service, error) { return tx.Service("svc-2") })
	put(t, s, putService, bareService("svc-3", "net-2", "web"), fullService("svc-1", "net-1", "web"))

	// Renaming frees the old name, and deleting frees a name within the
	// same transaction.
	put(t, s, putNetwork, bareNetwork("net-1", "bank"), bareNetwork("net-2", "shop"))
	update(t, s, func(tx store.Tx) error {
		if err := tx.DeleteNetwork("net-1"); err != nil {
			return err
		}
		return tx.PutNetwork(bareNetwork("net-3", "bank"))
	})
	same(t, "NetworkByName after the delete", read(t, s, func(tx store.ReadTx) (store.Network, error) { return tx.NetworkByName("bank") }), bareNetwork("net-3", "bank"))
	conflicts(t, s, "renaming onto a held name", func(tx store.Tx) error { return tx.PutNetwork(bareNetwork("net-3", "shop")) })
}

func testMemberHolders(t *testing.T, s store.Store) {
	member := func(id model.InterfaceID, svc model.ServiceID, name string, state api.LeaseState) store.Interface {
		i := bareInterface(id)
		i.Service, i.Member, i.State = svc, name, state
		return i
	}
	holder := func(svc model.ServiceID, name string) func(store.ReadTx) (store.Interface, error) {
		return func(tx store.ReadTx) (store.Interface, error) { return tx.Holder(svc, name) }
	}
	// Ended interfaces hold nothing, so a name may pass through many.
	put(t, s, putInterface,
		member("if-1", "svc-a", "m", api.Released), member("if-2", "svc-a", "m", api.Revoked),
		member("if-3", "svc-a", "m", api.Live), member("if-4", "svc-b", "m", api.Live),
		member("if-5", "svc-a", "", api.Live), member("if-6", "svc-a", "", api.Live))
	same(t, "Holder of svc-a's m", read(t, s, holder("svc-a", "m")), member("if-3", "svc-a", "m", api.Live))
	same(t, "Holder of svc-b's m", read(t, s, holder("svc-b", "m")), member("if-4", "svc-b", "m", api.Live))
	missing(t, s, "Holder of an unheld name", holder("svc-a", "n"))
	missing(t, s, "Holder of no name", holder("svc-a", ""))
	conflicts(t, s, "a second live holder of svc-a's m", func(tx store.Tx) error {
		return tx.PutInterface(member("if-7", "svc-a", "m", api.Live))
	})
	conflicts(t, s, "a holder taking a held name", func(tx store.Tx) error {
		return tx.PutInterface(member("if-5", "svc-a", "m", api.Live))
	})
	// Ending the holder frees the name within the same transaction.
	update(t, s, func(tx store.Tx) error {
		if err := tx.PutInterface(member("if-3", "svc-a", "m", api.Revoked)); err != nil {
			return err
		}
		return tx.PutInterface(member("if-7", "svc-a", "m", api.Live))
	})
	same(t, "Holder after the handover", read(t, s, holder("svc-a", "m")), member("if-7", "svc-a", "m", api.Live))
	// Putting the holder again is no conflict with itself.
	put(t, s, putInterface, member("if-7", "svc-a", "m", api.Live))
}

func testConflictLeavesTransactionUsable(t *testing.T, s store.Store) {
	update(t, s, func(tx store.Tx) error {
		if err := tx.PutNetwork(bareNetwork("net-1", "a")); err != nil {
			return err
		}
		if err := tx.PutNetwork(bareNetwork("net-2", "a")); !errors.Is(err, store.ErrConflict) {
			return fmt.Errorf("a second network named a: %v, want ErrConflict", err)
		}
		return tx.PutNetwork(bareNetwork("net-3", "b"))
	})
	same(t, "Networks", read(t, s, store.ReadTx.Networks), []store.Network{bareNetwork("net-1", "a"), bareNetwork("net-3", "b")})
}

// testRecordsAreCopies changes the slices of records it wrote and read, and
// checks that the store holds what was written.
func testRecordsAreCopies(t *testing.T, s store.Store) {
	n, r, e := fullNetwork("net-a", "a"), fullRelay("relay-a", "a"), fullEdge("net-a", "if-a", "if-b")
	h, a := fullHost("host-a", "a"), fullAdmin("admin-a", "a")
	written := struct {
		relays    []model.RelayID
		addrs     []api.RelayAddress
		ports     []store.EdgePorts
		hostNets  []model.NetworkID
		adminNets []model.NetworkID
	}{n.Relays, r.Addresses, e.Ports, h.Scope.Networks, a.Scope.Networks}
	want := []any{
		fullNetwork("net-a", "a"), fullRelay("relay-a", "a"), fullEdge("net-a", "if-a", "if-b"),
		fullHost("host-a", "a"), fullAdmin("admin-a", "a"),
	}
	stored := func(tx store.ReadTx) ([]any, error) {
		n, err := tx.Network("net-a")
		if err != nil {
			return nil, err
		}
		r, err := tx.Relay("relay-a")
		if err != nil {
			return nil, err
		}
		es, err := tx.Edges("net-a")
		if err != nil || len(es) != 1 {
			return nil, fmt.Errorf("edges %v: %w", es, err)
		}
		h, err := tx.Host("host-a")
		if err != nil {
			return nil, err
		}
		a, err := tx.Admin("admin-a")
		if err != nil {
			return nil, err
		}
		return []any{n, r, es[0], h, a}, nil
	}
	scribble := func(rs []any) {
		rs[0].(store.Network).Relays[0] = "relay-scribbled"
		rs[1].(store.Relay).Addresses[0].Local = addr("192.0.2.1")
		rs[2].(store.Edge).Ports[0].AB = 1
		rs[3].(store.Host).Scope.Networks[0] = "net-scribbled"
		rs[4].(store.Admin).Scope.Networks[0] = "net-scribbled"
	}
	update(t, s, func(tx store.Tx) error {
		return errors.Join(tx.PutNetwork(n), tx.PutRelay(r), tx.PutEdge(e), tx.PutHost(h), tx.PutAdmin(a))
	})
	written.relays[0], written.addrs[0].Local, written.ports[0].AB = "relay-scribbled", addr("192.0.2.1"), 1
	written.hostNets[0], written.adminNets[0] = "net-scribbled", "net-scribbled"
	same(t, "records after changing what was written", read(t, s, stored), want)
	scribble(read(t, s, stored))
	same(t, "records after changing what was read", read(t, s, stored), want)
	// A transaction that changes what it read and fails changes nothing.
	_, err := s.Update(t.Context(), func(tx store.Tx) error {
		rs, err := stored(tx)
		if err != nil {
			return err
		}
		scribble(rs)
		return errBoom
	})
	if !errors.Is(err, errBoom) {
		t.Fatalf("Update returned %v, want fn's error", err)
	}
	same(t, "records after a failed transaction changed what it read", read(t, s, stored), want)
	// Within a transaction, a record changed but not put stays as stored.
	update(t, s, func(tx store.Tx) error {
		rs, err := stored(tx)
		if err != nil {
			return err
		}
		scribble(rs)
		again, err := stored(tx)
		if err != nil {
			return err
		}
		same(t, "records read again in one transaction", again, want)
		return nil
	})
}

func testUpdateReadsItsOwnWrites(t *testing.T, s store.Store) {
	put(t, s, putNetwork, bareNetwork("net-old", "old"))
	n, v, i := fullNetwork("net-a", "a"), fullService("svc-a", "net-a", "web"), fullInterface("if-a")
	i.Network, i.Host = "net-a", "host-a"
	r := store.Rule{ID: "rule-a", Network: "net-a", From: "svc-a", Proto: model.AnyProto, Created: t0}
	e, h, rl := fullEdge("net-a", "if-a", "if-b"), fullHost("host-a", "h"), fullRelay("relay-a", "r")
	ad := fullAdmin("admin-a", "ad")
	q4 := store.Released4{Network: "net-a", Addr: addr("10.20.0.9"), At: at(1)}
	qp := store.ReleasedPort{Relay: "relay-a", Addr: addr("10.0.0.9"), Port: 30000, At: at(1)}
	check := func(tx store.ReadTx) error {
		got := []any{
			must(tx.Network("net-a")), must(tx.NetworkByName("a")), must(tx.Networks()),
			must(tx.Service("svc-a")), must(tx.ServiceByName("net-a", "web")), must(tx.Services("net-a")),
			must(tx.Interface("if-a")), must(tx.Interfaces("net-a")), must(tx.HostInterfaces("host-a")),
			must(tx.Rule("rule-a")), must(tx.Rules("net-a")),
			must(tx.Edges("net-a")), must(tx.RelayEdges("relay-a")),
			must(tx.Host("host-a")), must(tx.HostByName("h")), must(tx.HostByToken(h.TokenHash)), must(tx.Hosts()),
			must(tx.Admin("admin-a")), must(tx.AdminByName("ad")), must(tx.AdminByToken(ad.TokenHash)), must(tx.Admins()),
			must(tx.Relay("relay-a")), must(tx.RelayByName("r")), must(tx.RelayByToken(rl.TokenHash)), must(tx.Relays()),
			must(tx.Released4("net-a", at(2), 10)), must(tx.ReleasedPorts("relay-a", addr("10.0.0.9"), at(2), 10)),
			must(tx.PortCursor("relay-a", addr("10.0.0.9"))),
		}
		same(t, "records", got, []any{
			n, n, []store.Network{n},
			v, v, []store.Service{v},
			i, []store.Interface{i}, []store.Interface{i},
			r, []store.Rule{r},
			[]store.Edge{e}, []store.Edge{e},
			h, h, h, []store.Host{h},
			ad, ad, ad, []store.Admin{ad},
			rl, rl, rl, []store.Relay{rl},
			[]store.Released4{q4}, []store.ReleasedPort{qp},
			uint16(30001),
		})
		m, ok, err := tx.Meta("k")
		if err != nil || !ok || m != "v" {
			t.Errorf("Meta: %q %v %v", m, ok, err)
		}
		if _, err := tx.Network("net-old"); !errors.Is(err, store.ErrNotFound) {
			t.Errorf("deleted network: %v", err)
		}
		return nil
	}
	update(t, s, func(tx store.Tx) error {
		if err := errors.Join(
			tx.DeleteNetwork("net-old"), tx.PutNetwork(n), tx.PutService(v), tx.PutInterface(i), tx.PutRule(r),
			tx.PutEdge(e), tx.PutHost(h), tx.PutAdmin(ad), tx.PutRelay(rl), tx.PutReleased4(q4), tx.PutReleasedPort(qp),
			tx.SetPortCursor("relay-a", addr("10.0.0.9"), 30001), tx.SetMeta("k", "v"),
		); err != nil {
			return err
		}
		return check(tx)
	})
	if err := s.View(t.Context(), check); err != nil {
		t.Fatal(err)
	}
}

// must returns v, and records err for the read's caller in place of it.
func must[V any](v V, err error) any {
	if err != nil {
		return err
	}
	return v
}

func testFailedUpdateWritesNothing(t *testing.T, s store.Store) {
	base := bareNetwork("net-a", "a")
	svc := bareService("svc-a", "net-a", "web")
	h, rl := bareHost("host-b", "kept"), bareRelay("relay-b", "kept")
	update(t, s, func(tx store.Tx) error {
		if _, err := tx.Bump(); err != nil {
			return err
		}
		return errors.Join(tx.PutNetwork(base), tx.PutService(svc), tx.PutHost(h), tx.PutRelay(rl))
	})
	ch, err := s.Update(t.Context(), func(tx store.Tx) error {
		if _, err := tx.Bump(); err != nil {
			return err
		}
		tx.Touch(store.Change{Networks: []model.NetworkID{"net-a"}})
		if err := errors.Join(
			tx.PutNetwork(fullNetwork("net-a", "a")), tx.PutNetwork(bareNetwork("net-b", "b")),
			tx.DeleteService("svc-a"), tx.PutInterface(bareInterface("if-a")),
			tx.PutEdge(bareEdge("net-a", "if-a", "if-b")), tx.PutHost(bareHost("host-a", "h")),
			tx.PutRelay(bareRelay("relay-a", "r")), tx.DeleteHost("host-b"), tx.DeleteRelay("relay-b"),
			tx.PutReleased4(store.Released4{Network: "net-a", Addr: addr("10.0.0.1"), At: at(1)}),
			tx.PutReleasedPort(store.ReleasedPort{Relay: "relay-a", Addr: addr("10.0.0.1"), Port: 1, At: at(1)}),
			tx.SetPortCursor("relay-a", addr("10.0.0.1"), 2), tx.SetMeta("k", "v"),
		); err != nil {
			return err
		}
		return fmt.Errorf("wrapped: %w", errBoom)
	})
	if !errors.Is(err, errBoom) {
		t.Fatalf("Update returned %v, want fn's error", err)
	}
	if !ch.Empty() || ch.Revision != 0 {
		t.Errorf("a failed update returned %+v", ch)
	}
	same(t, "Networks", read(t, s, store.ReadTx.Networks), []store.Network{base})
	same(t, "Services", read(t, s, func(tx store.ReadTx) ([]store.Service, error) { return tx.Services("net-a") }), []store.Service{svc})
	same(t, "Interfaces", read(t, s, func(tx store.ReadTx) ([]store.Interface, error) { return tx.Interfaces("net-a") }), []store.Interface(nil))
	same(t, "Edges", edges(t, s, "net-a"), []store.Edge(nil))
	missing(t, s, "Host", func(tx store.ReadTx) (store.Host, error) { return tx.Host("host-a") })
	same(t, "deleted Host", read(t, s, func(tx store.ReadTx) (store.Host, error) { return tx.Host("host-b") }), h)
	same(t, "Relays", read(t, s, store.ReadTx.Relays), []store.Relay{rl})
	same(t, "Released4", read(t, s, func(tx store.ReadTx) ([]store.Released4, error) { return tx.Released4("net-a", at(2), 10) }), []store.Released4(nil))
	same(t, "ReleasedPorts", read(t, s, func(tx store.ReadTx) ([]store.ReleasedPort, error) {
		return tx.ReleasedPorts("relay-a", addr("10.0.0.1"), at(2), 10)
	}), []store.ReleasedPort(nil))
	same(t, "PortCursor", read(t, s, func(tx store.ReadTx) (uint16, error) { return tx.PortCursor("relay-a", addr("10.0.0.1")) }), uint16(0))
	same(t, "Meta", meta(t, s, "k"), metaValue{})
}

func testViewReturnsItsError(t *testing.T, s store.Store) {
	if err := s.View(t.Context(), func(store.ReadTx) error { return errBoom }); !errors.Is(err, errBoom) {
		t.Fatalf("View returned %v, want fn's error", err)
	}
}

func bump(t *testing.T, s store.Store) uint64 {
	t.Helper()
	var rev uint64
	ch := update(t, s, func(tx store.Tx) error {
		first, err := tx.Bump()
		if err != nil {
			return err
		}
		second, err := tx.Bump()
		if err != nil {
			return err
		}
		if first != second {
			return fmt.Errorf("Bump returned %d, then %d", first, second)
		}
		rev = first
		return nil
	})
	if ch.Revision != rev {
		t.Errorf("Change.Revision %d, Bump %d", ch.Revision, rev)
	}
	return rev
}

func testBump(t *testing.T, s store.Store) {
	if ch := update(t, s, func(tx store.Tx) error { return tx.SetMeta("k", "v") }); ch.Revision != 0 {
		t.Errorf("an update that bumps nothing returned revision %d", ch.Revision)
	}
	r1 := bump(t, s)
	if r1 == 0 {
		t.Fatal("Bump returned zero")
	}
	update(t, s, func(tx store.Tx) error { return tx.SetMeta("k", "w") })
	r2 := bump(t, s)
	if r2 <= r1 {
		t.Errorf("revision %d after %d", r2, r1)
	}
	_, err := s.Update(t.Context(), func(tx store.Tx) error {
		if _, err := tx.Bump(); err != nil {
			return err
		}
		return errBoom
	})
	if !errors.Is(err, errBoom) {
		t.Fatalf("Update returned %v, want fn's error", err)
	}
	if r3 := bump(t, s); r3 <= r2 {
		t.Errorf("revision %d after %d", r3, r2)
	}
}

func testTouch(t *testing.T, s store.Store) {
	ch := update(t, s, func(tx store.Tx) error {
		tx.Touch(store.Change{Networks: []model.NetworkID{"net-b", "net-a"}})
		tx.Touch(store.Change{Networks: []model.NetworkID{"net-a", "net-c"}, Hosts: []model.HostID{"host-2", "host-1", "host-2"}})
		tx.Touch(store.Change{Relays: []model.RelayID{"relay-a"}})
		return nil
	})
	same(t, "Change", ch, store.Change{
		Networks: []model.NetworkID{"net-a", "net-b", "net-c"},
		Hosts:    []model.HostID{"host-1", "host-2"},
		Relays:   []model.RelayID{"relay-a"},
	})
	var rev uint64
	ch = update(t, s, func(tx store.Tx) error {
		tx.Touch(store.Change{Hosts: []model.HostID{"host-1"}})
		var err error
		rev, err = tx.Bump()
		return err
	})
	same(t, "Change with a revision", ch, store.Change{Revision: rev, Hosts: []model.HostID{"host-1"}})
	if ch := update(t, s, func(store.Tx) error { return nil }); !ch.Empty() || ch.Revision != 0 {
		t.Errorf("an update that touches nothing returned %+v", ch)
	}
}

// writers is how many goroutines the concurrency tests run.
const writers = 16

func skipSingleThreaded(t *testing.T, s store.Store) {
	t.Helper()
	if _, ok := s.(SingleThreaded); ok {
		t.Skip("the store serves one transaction at a time")
	}
}

// parallel runs fn in writers goroutines and returns their errors.
func parallel(fn func(i int) error) []error {
	errs := make([]error, writers)
	var wg sync.WaitGroup
	for i := range writers {
		wg.Go(func() { errs[i] = fn(i) })
	}
	wg.Wait()
	return errs
}

// increment adds one to a counter kept in Meta.
func increment(tx store.Tx) (int, error) {
	v, _, err := tx.Meta("counter")
	if err != nil {
		return 0, err
	}
	n := 0
	if v != "" {
		if n, err = strconv.Atoi(v); err != nil {
			return 0, err
		}
	}
	n++
	return n, tx.SetMeta("counter", strconv.Itoa(n))
}

// testConcurrentIncrementsSerialize runs read-modify-write transactions on
// one value at once. Each must see the last one's write, so the backend has
// to serialize them, retrying the ones that conflict.
func testConcurrentIncrementsSerialize(t *testing.T, s store.Store) {
	skipSingleThreaded(t, s)
	errs := parallel(func(int) error {
		_, err := s.Update(t.Context(), func(tx store.Tx) error {
			_, err := increment(tx)
			return err
		})
		return err
	})
	if err := errors.Join(errs...); err != nil {
		t.Fatal(err)
	}
	same(t, "counter", meta(t, s, "counter"), metaValue{strconv.Itoa(writers), true})
}

// testConcurrentBumpsFollowCommitOrder runs transactions that increment one
// value and bump at once. The increments order the transactions, and their
// revisions must follow that order.
func testConcurrentBumpsFollowCommitOrder(t *testing.T, s store.Store) {
	skipSingleThreaded(t, s)
	type result struct {
		count int
		rev   uint64
	}
	results := make([]result, writers)
	errs := parallel(func(i int) error {
		ch, err := s.Update(t.Context(), func(tx store.Tx) error {
			n, err := increment(tx)
			if err != nil {
				return err
			}
			rev, err := tx.Bump()
			results[i] = result{n, rev}
			return err
		})
		if err == nil && ch.Revision != results[i].rev {
			err = fmt.Errorf("Change.Revision %d, Bump %d", ch.Revision, results[i].rev)
		}
		return err
	})
	if err := errors.Join(errs...); err != nil {
		t.Fatal(err)
	}
	slices.SortFunc(results, func(a, b result) int { return a.count - b.count })
	for i, r := range results {
		if r.count != i+1 {
			t.Fatalf("counts %v; want 1 to %d once each", results, writers)
		}
		if i > 0 && r.rev <= results[i-1].rev {
			t.Fatalf("revisions out of commit order: %v", results)
		}
	}
}

// testConcurrentPutsOfOneName puts networks with one name at once: one wins
// and every other sees a conflict.
func testConcurrentPutsOfOneName(t *testing.T, s store.Store) {
	skipSingleThreaded(t, s)
	errs := parallel(func(i int) error {
		_, err := s.Update(t.Context(), func(tx store.Tx) error {
			return tx.PutNetwork(bareNetwork(model.NetworkID(fmt.Sprintf("net-%02d", i)), "same"))
		})
		return err
	})
	won := 0
	for _, err := range errs {
		switch {
		case err == nil:
			won++
		case !errors.Is(err, store.ErrConflict):
			t.Errorf("a losing put returned %v, want ErrConflict", err)
		}
	}
	if won != 1 {
		t.Errorf("%d puts of one name succeeded, want 1", won)
	}
	if nets := read(t, s, store.ReadTx.Networks); len(nets) != 1 {
		t.Errorf("%d networks named same", len(nets))
	}
}
