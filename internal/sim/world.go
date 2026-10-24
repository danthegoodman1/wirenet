//wirenet:deterministic

package sim

import (
	"fmt"
	"maps"
	"net/netip"
	"slices"
	"strings"
	"time"

	"github.com/danthegoodman1/wirenet/internal/model"
	"github.com/danthegoodman1/wirenet/internal/prng"
)

// Epoch is the simulated wall clock at the start of every run.
func Epoch() time.Time { return time.Date(2030, 1, 1, 0, 0, 0, 0, time.UTC) }

// Failure is a property a run broke.
type Failure struct {
	Seed    uint64
	At      time.Duration
	Message string
	Trace   []string
}

func (f *Failure) Error() string {
	var b strings.Builder
	fmt.Fprintf(&b, "seed %d failed at %v: %s", f.Seed, f.At, f.Message)
	if len(f.Trace) > 0 {
		b.WriteString("\nlast events:\n  ")
		b.WriteString(strings.Join(f.Trace, "\n  "))
	}
	return b.String()
}

// Summary describes a run that passed.
type Summary struct {
	Seed                               uint64
	Events                             uint64
	Attaches, Detaches, Revokes, Rules int
	EgressGrants                       int
	// Policies counts wildcard and deny rules added and removed.
	Policies                              int
	AgentCrashes, RelayCrashes, CPCrashes int
	Reboots, Rebinds, Strays, Unnamed     int
	FlowsOK, FlowsDenied                  int
	Batches, Conflicts, Failovers         uint64
	Registrations, Withdrawals            uint64
	Acked, AckTimeouts                    uint64
	AttackerSent                          int
	// Members counts attaches that hold a member name, MemberConflicts
	// those refused because another interface held it, and Replacements
	// the holders an attach revoked.
	Members, MemberConflicts, Replacements int
	// RelayEdges counts the relay edges live at the end; RelaySplit those
	// whose two ends send through different relays, and RelayDrift those
	// whose ends agree on a relay other than the heaviest both find up.
	RelayEdges, RelaySplit, RelayDrift int
	// Rescopes counts changes to a host's scope, and ScopeRefusals the
	// attaches refused because the host's scope left their network out.
	Rescopes, ScopeRefusals int
}

func (s Summary) String() string {
	return fmt.Sprintf("seed %d: %d events; %d attaches, %d detaches, %d revokes, %d rule changes, %d egress grants, %d wildcard and deny changes; crashes agent %d relay %d cp %d, reboots %d, rebinds %d, strays %d, unnamed %d; flows ok %d denied %d; batches %d, conflicts %d, failovers %d, registrations %d, withdrawals %d, acked %d, ack timeouts %d, attacker sent %d; members %d, member conflicts %d, replacements %d; relay edges %d, split %d, drifted %d; rescopes %d, scope refusals %d",
		s.Seed, s.Events, s.Attaches, s.Detaches, s.Revokes, s.Rules, s.EgressGrants, s.Policies, s.AgentCrashes, s.RelayCrashes, s.CPCrashes,
		s.Reboots, s.Rebinds, s.Strays, s.Unnamed, s.FlowsOK, s.FlowsDenied, s.Batches, s.Conflicts, s.Failovers, s.Registrations, s.Withdrawals, s.Acked, s.AckTimeouts, s.AttackerSent,
		s.Members, s.MemberConflicts, s.Replacements, s.RelayEdges, s.RelaySplit, s.RelayDrift, s.Rescopes, s.ScopeRefusals)
}

// World is one simulated deployment.
type World struct {
	seed   uint64
	opts   Options
	loop   *Loop
	net    *Network
	under  *prng.Rand
	faults *prng.Rand
	work   *prng.Rand

	cp       *cpNode
	hosts    []*hostNode
	relays   []*relayNode
	orch     *orchestrator
	attacker *attacker

	// byPublic routes underlay packets to the node holding an address.
	byPublic map[netip.Addr]underlayNode
	// byKey names the interface each public key belongs to, as attach
	// answers reported it.
	byKey map[model.Key]model.InterfaceID
	// zoned holds each interface's zone already checked at a revision.
	zoned map[zoneAt]bool

	faultsOn bool
	failure  *Failure
	trace    []string
	tracing  bool
	summary  Summary
	flows    map[uint64]*flow
	nextFlow uint64
	// debugNS names a namespace whose batches the trace spells out.
	debugNS string
}

// New builds the world a seed describes.
func New(seed uint64) *World {
	return NewWith(seed, Swarm(seed))
}

// NewWith builds a world with explicit options.
func NewWith(seed uint64, opts Options) *World {
	w := &World{
		seed:     seed,
		opts:     opts,
		loop:     NewLoop(Epoch()),
		under:    prng.Stream(seed, "underlay"),
		faults:   prng.Stream(seed, "faults"),
		work:     prng.Stream(seed, "workload"),
		byPublic: map[netip.Addr]underlayNode{},
		byKey:    map[model.Key]model.InterfaceID{},
		zoned:    map[zoneAt]bool{},
		flows:    map[uint64]*flow{},
	}
	w.net = NewNetwork(w.loop, prng.Stream(seed, "network"), opts.CPDelayMin, opts.CPDelayMax)
	w.net.Faults = Faults{LossPercent: opts.LossPercent, PartitionPermille: opts.PartitionPermille, PartitionMax: opts.PartitionMax}
	w.summary.Seed = seed
	return w
}

// Trace keeps the last events for a failure report.
func (w *World) Trace() *World {
	w.tracing = true
	return w
}

// Options returns the run's options.
func (w *World) Options() Options { return w.opts }

func (w *World) now() time.Time { return w.loop.Now() }

func (w *World) elapsed() time.Duration { return w.now().Sub(Epoch()) }

func (w *World) logf(format string, args ...any) {
	if !w.tracing {
		return
	}
	w.trace = append(w.trace, fmt.Sprintf("%10v ", w.elapsed())+fmt.Sprintf(format, args...))
	if len(w.trace) > 400 && w.debugNS == "" {
		w.trace = w.trace[len(w.trace)-300:]
	}
}

// dbg logs only in a debugging run.
func (w *World) dbg(format string, args ...any) {
	if w.debugNS != "" {
		w.logf(format, args...)
	}
}

// fail records the first broken property.
func (w *World) fail(format string, args ...any) {
	if w.failure != nil {
		return
	}
	w.failure = &Failure{Seed: w.seed, At: w.elapsed(), Message: fmt.Sprintf(format, args...), Trace: slices.Clone(w.trace)}
}

// Run plays the whole run: setup, a phase of changes with faults, a quiet
// phase, then liveness checks.
func (w *World) Run() (Summary, error) {
	w.setup()
	w.faultsOn = true
	w.net.FaultsOn = true
	w.scheduleFaults()
	w.orch.start()
	w.every(100*time.Millisecond, w.checkSafety)
	end := Epoch().Add(w.opts.FaultTime)
	if !w.runUntil(end) {
		return w.summary, w.failure
	}
	w.faultsOn = false
	w.net.FaultsOn = false
	w.net.Heal()
	w.orch.stop()
	w.recover()
	if !w.runUntil(end.Add(w.opts.Quiesce)) {
		return w.summary, w.failure
	}
	w.checkLiveness()
	if w.failure != nil {
		return w.summary, w.failure
	}
	w.summary.Events = w.loop.Ran()
	for _, h := range w.hosts {
		if h.core != nil {
			w.summary.Batches += h.core.Stats.Batches
			w.summary.Conflicts += h.core.Stats.Conflicts
			w.summary.Failovers += h.core.Stats.Failovers
			w.summary.Registrations += h.core.Stats.Registrations
			w.summary.Withdrawals += h.core.Stats.Withdrawals
			w.summary.Acked += h.core.Stats.Acked
			w.summary.AckTimeouts += h.core.Stats.AckTimeouts
		}
	}
	return w.summary, nil
}

// eventsPerSecond bounds events per simulated second: more means a retry
// loop spinning without time passing.
const eventsPerSecond = 20000

func (w *World) runUntil(t time.Time) bool {
	budget := w.loop.Ran() + uint64(t.Sub(w.now()).Seconds()+1)*eventsPerSecond
	for w.failure == nil && w.loop.Pending() > 0 {
		if w.loop.Ran() > budget {
			w.fail("over %d events per simulated second: something spins", eventsPerSecond)
			break
		}
		if w.loop.events[0].at.After(t) {
			break
		}
		w.loop.Step()
	}
	w.loop.RunUntil(w.now())
	if w.now().Before(t) {
		w.loop.now = t
	}
	return w.failure == nil
}

// every runs fn on a period for the rest of the run.
func (w *World) every(d time.Duration, fn func()) {
	var tick func()
	tick = func() {
		fn()
		w.loop.After(d, tick)
	}
	w.loop.After(d, tick)
}

// setup creates the deployment: the control plane, relays, hosts, the
// orchestrator's networks, and the attacker.
func (w *World) setup() {
	w.cp = newCP(w)
	for i := range w.opts.Relays {
		w.relays = append(w.relays, newRelay(w, i))
	}
	for i := range w.opts.Hosts {
		w.hosts = append(w.hosts, newHost(w, i))
	}
	w.orch = newOrchestrator(w)
	w.orch.setup()
	for _, r := range w.relays {
		r.boot()
	}
	for _, h := range w.hosts {
		h.boot()
	}
	if w.opts.Attacker {
		w.attacker = newAttacker(w)
	}
}

// scheduleFaults draws node faults once a second while faults are on.
func (w *World) scheduleFaults() {
	w.every(time.Second, func() {
		if !w.faultsOn {
			return
		}
		if w.opts.CPCrashPermille > 0 && w.faults.Permille(w.opts.CPCrashPermille) {
			w.cp.crash(w.faults.Duration(100*time.Millisecond, 3*time.Second))
		}
		for _, r := range w.relays {
			if w.opts.RelayCrashPermille > 0 && w.faults.Permille(w.opts.RelayCrashPermille) {
				r.crash(w.faults.Duration(100*time.Millisecond, 3*time.Second))
			}
			w.net.MaybePartition(r.node())
		}
		for _, h := range w.hosts {
			if w.opts.RebootPermille > 0 && w.faults.Permille(w.opts.RebootPermille) {
				h.reboot()
				continue
			}
			if w.opts.NATRebindPermille > 0 && w.faults.Permille(w.opts.NATRebindPermille) {
				h.rebind()
			}
			if w.opts.UnnamePermille > 0 && w.orch.unnamer.Permille(w.opts.UnnamePermille) {
				w.orch.unname(h)
			}
			w.net.MaybePartition(h.node())
		}
		w.net.MaybePartition(cpNodeName)
	})
}

// recover restarts everything down once faults stop.
func (w *World) recover() {
	w.cp.restart()
	for _, r := range w.relays {
		r.restart()
	}
	for _, h := range w.hosts {
		h.restart()
	}
}

func (w *World) hostByID(id model.HostID) *hostNode {
	for _, h := range w.hosts {
		if h.id == id {
			return h
		}
	}
	return nil
}

func sortedKeys[K ~string, V any](m map[K]V) []K { return slices.Sorted(maps.Keys(m)) }

// ParseSeed reads a seed in decimal, or as a git commit hash, whose first 16
// hex digits become the seed.
func ParseSeed(s string) (uint64, error) {
	var v uint64
	if _, err := fmt.Sscan(s, &v); err == nil && fmt.Sprint(v) == s {
		return v, nil
	}
	if len(s) < 16 {
		return 0, fmt.Errorf("seed %q is neither a number nor a commit hash", s)
	}
	for _, c := range s[:16] {
		var d uint64
		switch {
		case c >= '0' && c <= '9':
			d = uint64(c - '0')
		case c >= 'a' && c <= 'f':
			d = uint64(c-'a') + 10
		default:
			return 0, fmt.Errorf("seed %q is neither a number nor a commit hash", s)
		}
		v = v<<4 | d
	}
	return v, nil
}
