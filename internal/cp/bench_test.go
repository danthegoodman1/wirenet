package cp

import (
	"errors"
	"fmt"
	"net/netip"
	"testing"

	"github.com/danthegoodman1/wirenet/internal/api"
	"github.com/danthegoodman1/wirenet/internal/model"
	"github.com/danthegoodman1/wirenet/internal/store"
	"github.com/danthegoodman1/wirenet/internal/store/mem"
	"github.com/danthegoodman1/wirenet/internal/store/pgstore/pgtest"
)

// errRollback ends a benchmark's transaction without committing it, so every
// iteration acts on the same network.
var errRollback = errors.New("rollback")

// benchNetwork builds a network the size the attach plan measures: web
// reaches db and cache, 15 db and 5 cache interfaces, so a web attach has
// degree 20, beside 200 web interfaces over four hosts and two relays.
func benchNetwork(b *testing.B, s store.Store) *fixture {
	f := newFixture(b, s)
	var relays []model.RelayID
	for i := range 2 {
		f.update(func(tx store.Tx) error {
			r, _, err := f.p.CreateRelay(tx, f.now, api.CreateRelay{
				Name: fmt.Sprintf("r%d", i),
				Addresses: []api.RelayAddress{{
					Local:      netip.AddrFrom4([4]byte{10, 0, 0, byte(1 + i)}),
					Advertised: netip.AddrFrom4([4]byte{198, 51, 100, byte(1 + i)}),
				}},
				PortLo: 10000, PortHi: 60000, ProbePort: 9999,
			})
			relays = append(relays, r.ID)
			return err
		})
	}
	f.network(api.CreateNetwork{Name: "bench", Prefix4: netip.MustParsePrefix("10.42.0.0/16"), Relays: relays})
	for _, svc := range []string{"web", "db", "cache"} {
		f.service("bench", svc, true)
	}
	f.rule("bench", "web", "db", model.TCP, 5432)
	f.rule("bench", "web", "cache", model.TCP, 6379)
	for i := range 220 {
		svc := "web"
		switch {
		case i < 15:
			svc = "db"
		case i < 20:
			svc = "cache"
		}
		f.attach(fmt.Sprintf("h%d", i%4), "bench", svc)
	}
	return f
}

func benchStores(b *testing.B, fn func(b *testing.B, f *fixture)) {
	b.Run("mem", func(b *testing.B) { fn(b, benchNetwork(b, mem.New())) })
	b.Run("postgres", func(b *testing.B) { fn(b, benchNetwork(b, pgtest.Open(b))) })
}

// BenchmarkAttach times one degree-20 attach into a network of 220
// interfaces, rolled back so every iteration sees the same network.
func BenchmarkAttach(b *testing.B) {
	benchStores(b, func(b *testing.B, f *fixture) {
		h := f.host("h1")
		priv, _ := model.NewPrivateKey(f.rng)
		pub := priv.Public()
		for b.Loop() {
			id, _ := model.NewID(model.InterfacePrefix, f.rng)
			_, err := f.s.Update(b.Context(), func(tx store.Tx) error {
				if _, _, err := f.p.Attach(tx, f.now, h, api.AttachRequest{
					Interface: model.InterfaceID(id), Network: "bench", Service: "web",
					PublicKey: pub, ListenPort: 40000,
				}); err != nil {
					return err
				}
				return errRollback
			})
			if !errors.Is(err, errRollback) {
				b.Fatal(err)
			}
		}
	})
}

// BenchmarkCreateRule times a rule that connects web to a new port of db
// across the same network, rolled back.
func BenchmarkCreateRule(b *testing.B) {
	benchStores(b, func(b *testing.B, f *fixture) {
		for b.Loop() {
			_, err := f.s.Update(b.Context(), func(tx store.Tx) error {
				if _, err := f.p.CreateRule(tx, f.now, Global(), "bench", api.CreateRule{
					From: "web", To: "db", Proto: model.TCP, Ports: model.PortRange{Lo: 8080, Hi: 8080},
				}); err != nil {
					return err
				}
				return errRollback
			})
			if !errors.Is(err, errRollback) {
				b.Fatal(err)
			}
		}
	})
}
