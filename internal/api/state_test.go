package api

import (
	"testing"

	"github.com/danthegoodman1/wirenet/internal/model"
)

// TestAnUpdateOlderThanAnAttachKeepsItsNetwork covers an attach answer that
// delivers a network, followed by a poll answer computed before the attach,
// which does not list the network yet.
func TestAnUpdateOlderThanAnAttachKeepsItsNetwork(t *testing.T) {
	h := NewHostState()
	if err := h.Apply(StateUpdate{Generation: 10, Present: []NetworkRef{{Network: "net-a", Revision: 10}},
		Networks: []NetworkState{{Network: "net-a", Revision: 10}}}); err != nil {
		t.Fatal(err)
	}
	h.Merge(NetworkState{Network: "net-b", Revision: 31})
	if err := h.Apply(StateUpdate{Generation: 12, Present: []NetworkRef{{Network: "net-a", Revision: 12}},
		Networks: []NetworkState{{Network: "net-a", Revision: 12}}}); err != nil {
		t.Fatal(err)
	}
	if _, ok := h.Networks["net-b"]; !ok {
		t.Fatal("an update older than the attach dropped its network")
	}
	// An update at or past the network's revision that leaves it out means
	// the host no longer holds it.
	if err := h.Apply(StateUpdate{Generation: 40, Present: []NetworkRef{{Network: "net-a", Revision: 12}}}); err != nil {
		t.Fatal(err)
	}
	if _, ok := h.Networks["net-b"]; ok {
		t.Fatal("a newer update left a dropped network in place")
	}
	if h.Generation != 40 {
		t.Fatalf("generation %d", h.Generation)
	}
}

// TestALateAttachAnswerLeavesADroppedNetworkDropped covers an attach answer
// delayed past a poll that dropped its network, as a rescope does: the
// poll's generation passed the answer's revision, so the answer predates
// the drop.
func TestALateAttachAnswerLeavesADroppedNetworkDropped(t *testing.T) {
	h := NewHostState()
	if err := h.Apply(StateUpdate{Generation: 10, Present: []NetworkRef{{Network: "net-a", Revision: 10}},
		Networks: []NetworkState{{Network: "net-a", Revision: 10}}}); err != nil {
		t.Fatal(err)
	}
	if err := h.Apply(StateUpdate{Generation: 11, Present: []NetworkRef{}}); err != nil {
		t.Fatal(err)
	}
	h.Merge(NetworkState{Network: "net-a", Revision: 10})
	h.Merge(NetworkState{Network: "net-b", Revision: 11})
	if len(h.Networks) != 0 {
		t.Fatalf("late attach answers brought back %v", h.NetworkIDs())
	}
	// An answer past the generation comes from an attach the poll
	// predates.
	h.Merge(NetworkState{Network: "net-a", Revision: 12})
	if n, ok := h.Networks["net-a"]; !ok || n.Revision != 12 {
		t.Fatalf("an attach answer newer than the poll was dropped: %v", h.NetworkIDs())
	}
}

func TestAnUpdateMustCarryWhatItLists(t *testing.T) {
	h := NewHostState()
	err := h.Apply(StateUpdate{Generation: 5, Present: []NetworkRef{{Network: model.NetworkID("net-a"), Revision: 5}}})
	if err == nil {
		t.Fatal("accepted an update listing a network it never carried")
	}
}

// TestAnUpdateThatFailsACheckChangesNothing applies an update whose first
// network is sound and whose second carries no identifier: the held state
// keeps both networks and its generation as they were.
func TestAnUpdateThatFailsACheckChangesNothing(t *testing.T) {
	h := NewHostState()
	if err := h.Apply(StateUpdate{Generation: 10,
		Present:  []NetworkRef{{Network: "net-a", Revision: 10}, {Network: "net-b", Revision: 10}},
		Networks: []NetworkState{{Network: "net-a", Revision: 10}, {Network: "net-b", Revision: 10}}}); err != nil {
		t.Fatal(err)
	}
	bad := StateUpdate{Generation: 20,
		Present:  []NetworkRef{{Network: "net-a", Revision: 20}, {Network: "net-b", Revision: 20}},
		Networks: []NetworkState{{Network: "net-a", Revision: 20}, {}}}
	if err := h.Apply(bad); err == nil {
		t.Fatal("accepted a network with no identifier")
	}
	if h.Generation != 10 || len(h.Networks) != 2 || h.Networks["net-a"].Revision != 10 {
		t.Fatalf("a refused update changed the state: generation %d, net-a %+v", h.Generation, h.Networks["net-a"])
	}
}
