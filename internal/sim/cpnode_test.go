package sim

import (
	"testing"

	"github.com/danthegoodman1/wirenet/internal/api"
	"github.com/danthegoodman1/wirenet/internal/cp"
	"github.com/danthegoodman1/wirenet/internal/model"
	"github.com/danthegoodman1/wirenet/internal/store"
)

// TestAParkedPollWakesForItsNetwork holds the simulator's control plane to
// the server hub's contract: a commit to a network a host holds answers the
// host's parked poll, though the commit names no host.
func TestAParkedPollWakesForItsNetwork(t *testing.T) {
	w := New(1)
	c := newCP(w)
	var host model.HostID
	if _, err := c.update(func(tx store.Tx) error {
		h, _, err := c.plane.CreateHost(tx, w.now(), cp.Global(), api.CreateHost{Name: "h"})
		if err != nil {
			return err
		}
		host = h.ID
		if _, err := c.plane.CreateNetwork(tx, w.now(), api.CreateNetwork{Name: "n"}); err != nil {
			return err
		}
		for _, svc := range []string{"a", "b"} {
			if _, err := c.plane.CreateService(tx, w.now(), cp.Global(), "n", api.CreateService{Name: svc}); err != nil {
				return err
			}
		}
		_, _, err = c.plane.Attach(tx, w.now(), host, api.AttachRequest{
			Interface: "if-a", Network: "n", Service: "a", PublicKey: model.Key{1}, ListenPort: 1,
		})
		return err
	}); err != nil {
		t.Fatal(err)
	}
	var gen uint64
	c.view(func(tx store.ReadTx) error {
		gen, _, _ = cp.HostGeneration(tx, host)
		return nil
	})
	woke := false
	c.handlePoll(host, gen, func(api.StateUpdate) { woke = true })
	if woke {
		t.Fatal("a poll with nothing new answered at once")
	}
	if _, err := c.update(func(tx store.Tx) error {
		_, err := c.plane.CreateRule(tx, w.now(), cp.Global(), "n", api.CreateRule{From: "a", To: "b", Proto: model.TCP, Ports: model.PortRange{Lo: 1, Hi: 1}})
		return err
	}); err != nil {
		t.Fatal(err)
	}
	if !woke {
		t.Fatal("a rule change in the host's network left its poll parked")
	}
}
