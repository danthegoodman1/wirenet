package cp

import (
	"errors"
	"net/netip"
	"slices"
	"testing"
	"time"

	"github.com/danthegoodman1/wirenet/internal/api"
	"github.com/danthegoodman1/wirenet/internal/model"
	"github.com/danthegoodman1/wirenet/internal/store"
)

var edgeEndpoint = netip.MustParseAddrPort("203.0.113.7:0")

// gateway attaches a gateway interface on a host development machines can
// reach.
func (f *fixture) gateway(host, net, svc string) store.Interface {
	f.t.Helper()
	if _, ok := f.hosts[host]; !ok {
		f.update(func(tx store.Tx) error {
			h, _, err := f.p.CreateHost(tx, f.now, Global(), api.CreateHost{Name: host, Endpoint: edgeEndpoint})
			f.hosts[host] = h.ID
			return err
		})
	}
	priv, _ := model.NewPrivateKey(f.rng)
	id, _ := model.NewID(model.InterfacePrefix, f.rng)
	var i store.Interface
	f.update(func(tx store.Tx) error {
		var err error
		i, _, err = f.p.Attach(tx, f.now, f.hosts[host], api.AttachRequest{
			Interface: model.InterfaceID(id), Network: net, Service: svc, Kind: api.Gateway,
			PublicKey: priv.Public(), ListenPort: 51820,
		})
		return err
	})
	return i
}

// device registers a development machine's public key behind a gateway.
func (f *fixture) device(net, svc string, gw model.InterfaceID, ttl time.Duration) (store.Interface, error) {
	priv, _ := model.NewPrivateKey(f.rng)
	var d store.Interface
	err := f.tryUpdate(func(tx store.Tx) error {
		var err error
		d, err = f.p.CreateDevice(tx, f.now, Global(), net, api.CreateDevice{Service: svc, Gateway: gw, PublicKey: priv.Public(), TTL: ttl})
		return err
	})
	return d, err
}

func peerOf(u api.StateUpdate, iface, peer model.InterfaceID) (api.Peer, bool) {
	for _, n := range u.Networks {
		if i, ok := n.Interface(iface); ok {
			for _, p := range i.Peers {
				if p.Interface == peer {
					return p, true
				}
			}
		}
	}
	return api.Peer{}, false
}

// shopWithDevices builds a network where development machines reach db and
// nothing else, through one gateway.
func shopWithDevices(f *fixture) (gw, db, secret store.Interface) {
	relay := f.relay("r")
	f.network(api.CreateNetwork{Name: "shop", Prefix4: netip.MustParsePrefix("10.42.0.0/16"), Relays: []model.RelayID{relay}})
	f.service("shop", "edge", true)
	f.service("shop", "dev", true)
	f.service("shop", "db", true)
	f.service("shop", "secret", true)
	f.rule("shop", "dev", "db", model.TCP, 5432)
	gw = f.gateway("edge", "shop", "edge")
	db, _ = f.attach("h2", "shop", "db")
	secret, _ = f.attach("h2", "shop", "secret")
	return gw, db, secret
}

func TestADeviceReachesWhatPolicyGrantsThroughItsGateway(t *testing.T) {
	eachStore(t, func(t *testing.T, f *fixture) {
		gw, db, secret := shopWithDevices(f)
		laptop, err := f.device("shop", "dev", gw.ID, 24*time.Hour)
		if err != nil {
			t.Fatal(err)
		}
		other, err := f.device("shop", "dev", gw.ID, 24*time.Hour)
		if err != nil {
			t.Fatal(err)
		}
		edge, h2 := f.state("edge"), f.state("h2")

		// The gateway holds each machine as a dial-in peer allowed its own
		// addresses alone, so one machine cannot send as another.
		for _, d := range []store.Interface{laptop, other} {
			p, ok := peerOf(edge, gw.ID, d.ID)
			want := []netip.Prefix{netip.PrefixFrom(d.Addr6, 128), netip.PrefixFrom(d.Addr4, 32)}
			if !ok || !p.DialsIn || len(p.Relays) != 0 || !slices.Equal(p.Allowed, want) {
				t.Fatalf("gateway's peer for %s: %+v, want dial-in allowed %v", d.ID, p, want)
			}
		}
		// db's entry for the gateway carries both machines' addresses, so
		// db enforces policy against them; secret, which policy keeps from
		// the machines, has no peer for the gateway at all.
		p, ok := peerOf(h2, db.ID, gw.ID)
		if !ok || len(p.Fronts) != 2 {
			t.Fatalf("db's peer for the gateway: %+v", p)
		}
		for _, fr := range p.Fronts {
			if fr.Interface != laptop.ID && fr.Interface != other.ID {
				t.Fatalf("db's gateway entry fronts %s", fr.Interface)
			}
		}
		if p, ok := peerOf(h2, secret.ID, gw.ID); ok {
			t.Fatalf("secret peers with the gateway: %+v", p)
		}

		// The config points at the gateway's host and routes the network.
		var c api.DeviceConfig
		if err := f.s.View(t.Context(), func(tx store.ReadTx) error {
			c, err = DeviceConfig(tx, laptop.ID)
			return err
		}); err != nil {
			t.Fatal(err)
		}
		if c.GatewayAddress != netip.AddrPortFrom(edgeEndpoint.Addr(), gw.ListenPort) || c.GatewayKey != gw.PublicKey || c.DNS != gw.Addr6 || len(c.Routes) != 2 {
			t.Fatalf("config %+v", c)
		}
	})
}

// TestAGatewayWhoseDevicesReachKeepsALoopbackPairAlive puts db beside a
// gateway whose development machines reach it under `dev -> db`, though
// nothing grants the gateway's own service anything, and lets db reach
// the machines too, which the gateway's shield turns away: the gateway's
// peer for each db carries keepalive and db's for the gateway does not,
// whichever has the lower ID, since the machines' first connections leave
// from the gateway's device and db opens none.
func TestAGatewayWhoseDevicesReachKeepsALoopbackPairAlive(t *testing.T) {
	eachStore(t, func(t *testing.T, f *fixture) {
		gw, _, _ := shopWithDevices(f)
		f.rule("shop", "db", "dev", model.TCP, 22)
		if _, err := f.device("shop", "dev", gw.ID, 24*time.Hour); err != nil {
			t.Fatal(err)
		}
		lower := false
		for range 6 {
			db, _ := f.attach("edge", "shop", "db")
			lower = lower || db.ID < gw.ID
			st := f.state("edge")
			toDB, ok := peerOf(st, gw.ID, db.ID)
			toGW, ok2 := peerOf(st, db.ID, gw.ID)
			if !ok || !ok2 || !toDB.Keepalive || toGW.Keepalive {
				t.Errorf("gateway toward %s %+v, it toward the gateway %+v: want the gateway alone keeping alive", db.ID, toDB, toGW)
			}
		}
		if !lower {
			t.Fatal("no db drew an identifier below the gateway's, where the lower ID alone would arm db, so the test proves nothing")
		}
	})
}

func TestARevokedDeviceLeavesItsGatewayAndBackendsAtOnce(t *testing.T) {
	eachStore(t, func(t *testing.T, f *fixture) {
		gw, db, _ := shopWithDevices(f)
		laptop, err := f.device("shop", "dev", gw.ID, 24*time.Hour)
		if err != nil {
			t.Fatal(err)
		}
		f.update(func(tx store.Tx) error { return f.p.Revoke(tx, f.now, laptop.ID) })
		if p, ok := peerOf(f.state("edge"), gw.ID, laptop.ID); ok {
			t.Fatalf("the gateway still holds the revoked machine: %+v", p)
		}
		if p, ok := peerOf(f.state("h2"), db.ID, gw.ID); ok && len(p.Fronts) != 0 {
			t.Fatalf("db's gateway entry still fronts %+v", p.Fronts)
		}
	})
}

func TestADeviceLeaseEndsWithItsTerm(t *testing.T) {
	eachStore(t, func(t *testing.T, f *fixture) {
		gw, _, _ := shopWithDevices(f)
		if _, err := f.device("shop", "dev", gw.ID, MaxDeviceTTL+time.Hour); err == nil {
			t.Fatal("a term past the maximum was accepted")
		}
		laptop, err := f.device("shop", "dev", gw.ID, time.Hour)
		if err != nil {
			t.Fatal(err)
		}
		// The gateway's agent keeps renewing its own lease; nothing renews
		// the machine's.
		for range 3 {
			f.now = f.now.Add(25 * time.Minute)
			f.update(func(tx store.Tx) error {
				if _, err := f.p.Renew(tx, f.now, f.host("edge"), []model.InterfaceID{gw.ID, laptop.ID}); err != nil {
					return err
				}
				_, err := f.p.Sweep(tx, f.now)
				return err
			})
		}
		if p, ok := peerOf(f.state("edge"), gw.ID, laptop.ID); ok && !p.Draining {
			t.Fatalf("the gateway still holds the machine past its term: %+v", p)
		}
	})
}

func TestADeviceHasIPv4OnlyWhereItsGatewayDoes(t *testing.T) {
	eachStore(t, func(t *testing.T, f *fixture) {
		relay := f.relay("r")
		f.network(api.CreateNetwork{Name: "shop", Prefix4: netip.MustParsePrefix("10.42.0.0/16"), Relays: []model.RelayID{relay}})
		f.service("shop", "edge", false)
		f.service("shop", "dev", true)
		gw := f.gateway("edge", "shop", "edge")
		laptop, err := f.device("shop", "dev", gw.ID, time.Hour)
		if err != nil {
			t.Fatal(err)
		}
		if laptop.Addr4.IsValid() {
			t.Fatalf("a machine behind an IPv6-only gateway drew %v", laptop.Addr4)
		}
	})
}

// interfaceState reads one interface's lease state, or "" once it is gone.
func (f *fixture) interfaceState(id model.InterfaceID) api.LeaseState {
	f.t.Helper()
	var st api.LeaseState
	if err := f.s.View(f.t.Context(), func(tx store.ReadTx) error {
		i, err := tx.Interface(id)
		if errors.Is(err, store.ErrNotFound) {
			return nil
		}
		st = i.State
		return err
	}); err != nil {
		f.t.Fatal(err)
	}
	return st
}

// TestADeviceEndsWithItsGateway ends a gateway each way an interface ends.
// Its development machines end with it, so once the sweep deletes the
// gateway nothing names it: the gateway's host gets a state it can apply,
// and an interface attached later under the gateway's identifier fronts
// nothing.
func TestADeviceEndsWithItsGateway(t *testing.T) {
	ends := []struct {
		name string
		end  func(f *fixture, gw store.Interface, keep func())
	}{
		{"release", func(f *fixture, gw store.Interface, _ func()) {
			f.update(func(tx store.Tx) error { return f.p.Release(tx, f.now, gw.Host, []model.InterfaceID{gw.ID}) })
		}},
		{"revoke", func(f *fixture, gw store.Interface, _ func()) {
			f.update(func(tx store.Tx) error { return f.p.Revoke(tx, f.now, gw.ID) })
		}},
		{"expiry", func(f *fixture, gw store.Interface, keep func()) {
			f.now = f.now.Add(f.p.Config.LeaseTTL + time.Second)
			keep()
		}},
	}
	for _, c := range ends {
		t.Run(c.name, func(t *testing.T) {
			eachStore(t, func(t *testing.T, f *fixture) {
				gw, db, secret := shopWithDevices(f)
				laptop, err := f.device("shop", "dev", gw.ID, 24*time.Hour)
				if err != nil {
					t.Fatal(err)
				}
				// The backends' agent renews as time passes, and the sweep
				// runs.
				keep := func() {
					f.update(func(tx store.Tx) error {
						if _, err := f.p.Renew(tx, f.now, f.host("h2"), []model.InterfaceID{db.ID, secret.ID}); err != nil {
							return err
						}
						_, err := f.p.Sweep(tx, f.now)
						return err
					})
				}
				c.end(f, gw, keep)
				if st := f.interfaceState(laptop.ID); st != api.Revoked {
					t.Fatalf("the machine is %s once its gateway ended", st)
				}
				if p, ok := peerOf(f.state("h2"), db.ID, gw.ID); ok && len(p.Fronts) != 0 {
					t.Fatalf("db's entry for the ended gateway still fronts %+v", p.Fronts)
				}
				for _, d := range []time.Duration{f.p.Config.DrainGrace + time.Second, f.p.Config.Retention + time.Second} {
					f.now = f.now.Add(d)
					keep()
				}
				if st := f.interfaceState(gw.ID); st != "" {
					t.Fatalf("the gateway is %s past its retention", st)
				}
				u := f.state("edge")
				for _, n := range u.Networks {
					if n.Network == "" {
						t.Fatalf("the gateway's host gets a network with no identifier: %+v", u)
					}
				}
				if err := api.NewHostState().Apply(u); err != nil {
					t.Fatalf("the gateway's host cannot apply its state: %v", err)
				}

				// A host attaching under the deleted gateway's identifier
				// becomes no machine's gateway.
				priv, _ := model.NewPrivateKey(f.rng)
				f.update(func(tx store.Tx) error {
					_, _, err := f.p.Attach(tx, f.now, f.host("other"), api.AttachRequest{
						Interface: gw.ID, Network: "shop", Service: "edge", Kind: api.Gateway, PublicKey: priv.Public(), ListenPort: 1,
					})
					return err
				})
				if p, ok := peerOf(f.state("h2"), db.ID, gw.ID); ok && len(p.Fronts) != 0 {
					t.Fatalf("an interface reusing the gateway's identifier fronts %+v", p.Fronts)
				}
			})
		})
	}
}

// TestADeviceIsFrontedOnlyFromItsGatewaysHost moves a live gateway's record
// to another host, as a reused identifier would, and checks that its
// development machine stays unfronted rather than follow it.
func TestADeviceIsFrontedOnlyFromItsGatewaysHost(t *testing.T) {
	eachStore(t, func(t *testing.T, f *fixture) {
		gw, db, _ := shopWithDevices(f)
		if _, err := f.device("shop", "dev", gw.ID, 24*time.Hour); err != nil {
			t.Fatal(err)
		}
		if p, ok := peerOf(f.state("h2"), db.ID, gw.ID); !ok || len(p.Fronts) != 1 {
			t.Fatalf("db's entry for the gateway before the move: %+v", p)
		}
		other := f.host("other")
		f.update(func(tx store.Tx) error {
			g, err := tx.Interface(gw.ID)
			if err != nil {
				return err
			}
			g.Host = other
			return tx.PutInterface(g)
		})
		if p, ok := peerOf(f.state("h2"), db.ID, gw.ID); ok && len(p.Fronts) != 0 {
			t.Fatalf("a gateway record on another host fronts %+v", p.Fronts)
		}
	})
}

// TestAHostGetsNoStateForADeviceRecordAlone leaves a development machine's
// record on a host that builds nothing else in its network: the host's
// state neither lists the network nor carries an empty one.
func TestAHostGetsNoStateForADeviceRecordAlone(t *testing.T) {
	eachStore(t, func(t *testing.T, f *fixture) {
		gw, _, _ := shopWithDevices(f)
		if _, err := f.device("shop", "dev", gw.ID, 24*time.Hour); err != nil {
			t.Fatal(err)
		}
		f.update(func(tx store.Tx) error { return tx.DeleteInterface(gw.ID) })
		if u := f.state("edge"); len(u.Networks) != 0 || len(u.Present) != 0 {
			t.Fatalf("a host holding only a device record gets %+v", u)
		}
	})
}

// TestReleaseLeavesADeviceToItsGateway has the gateway's host release one
// of its development machines: the machine stays live, since it ends only
// by revocation, by its term, or with its gateway.
func TestReleaseLeavesADeviceToItsGateway(t *testing.T) {
	eachStore(t, func(t *testing.T, f *fixture) {
		gw, _, _ := shopWithDevices(f)
		laptop, err := f.device("shop", "dev", gw.ID, 24*time.Hour)
		if err != nil {
			t.Fatal(err)
		}
		f.update(func(tx store.Tx) error { return f.p.Release(tx, f.now, gw.Host, []model.InterfaceID{laptop.ID}) })
		if st := f.interfaceState(laptop.ID); st != api.Live {
			t.Fatalf("a released device is %s", st)
		}
		if p, ok := peerOf(f.state("edge"), gw.ID, laptop.ID); !ok || p.Draining {
			t.Fatalf("the gateway's peer for the machine: %+v", p)
		}
	})
}
