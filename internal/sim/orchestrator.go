//wirenet:deterministic

package sim

import (
	"errors"
	"fmt"
	"net/netip"
	"slices"
	"time"

	agentcore "github.com/danthegoodman1/wirenet/internal/agent/core"
	"github.com/danthegoodman1/wirenet/internal/api"
	"github.com/danthegoodman1/wirenet/internal/cp"
	"github.com/danthegoodman1/wirenet/internal/kernel/kmodel"
	"github.com/danthegoodman1/wirenet/internal/model"
	"github.com/danthegoodman1/wirenet/internal/prng"
	"github.com/danthegoodman1/wirenet/internal/store"
)

// netIntent is a network as the orchestrator made it, with its policy
// ledger: the rule set after every change, by the revision it produced.
type netIntent struct {
	id       model.NetworkID
	name     string
	services []*svcIntent
	rules    map[model.RuleID]store.Rule
	history  []ruleSet
}

type ruleSet struct {
	revision uint64
	rules    []store.Rule
}

type svcIntent struct {
	id           model.ServiceID
	name         string
	ipv4         bool
	addr6, addr4 netip.Addr
}

type ifState int

const (
	attaching ifState = iota
	attached
	detachingState
)

// ifIntent is an interface the orchestrator asked for and the workload
// running in it.
type ifIntent struct {
	id           model.InterfaceID
	network      model.NetworkID
	service      model.ServiceID
	host         *hostNode
	ns           string
	addr6, addr4 netip.Addr
	key          model.Key
	state        ifState
	held         *kmodel.Netns
	flows        []*flow
	// member is the name it asked to hold among its service's members.
	member string
}

type orchestrator struct {
	w   *World
	rng *prng.Rand
	// egress draws internet grants, on a stream of its own so the other
	// draws stay as they were; policy draws wildcard and deny rules,
	// unnamer which namespace loses its name, member which workloads hold
	// member names, and scope which networks a host may attach into,
	// likewise.
	egress    *prng.Rand
	policy    *prng.Rand
	unnamer   *prng.Rand
	member    *prng.Rand
	scope     *prng.Rand
	networks  []*netIntent
	ifaces    map[model.InterfaceID]*ifIntent
	attaching map[string]*pendingAttach
	// requested holds the member name each answered attach asked for.
	requested map[model.InterfaceID]string
	names     int
	running   bool
}

// pendingAttach is an attach the orchestrator keeps retrying, by workload
// name, until an agent answers it.
type pendingAttach struct {
	name string
	net  *netIntent
	svc  *svcIntent
	host *hostNode
	// member, if set, is the name to hold, replacing its holder if replace
	// is set.
	member  string
	replace bool
}

// retryAfter is how long the orchestrator waits before retrying a call an
// agent did not answer.
const retryAfter = 500 * time.Millisecond

func newOrchestrator(w *World) *orchestrator {
	return &orchestrator{
		w: w, rng: prng.Stream(w.seed, "orchestrator"), egress: prng.Stream(w.seed, "egress"), policy: prng.Stream(w.seed, "policy"),
		unnamer: prng.Stream(w.seed, "unname"), member: prng.Stream(w.seed, "member"), scope: prng.Stream(w.seed, "scope"),
		ifaces: map[model.InterfaceID]*ifIntent{}, attaching: map[string]*pendingAttach{},
		requested: map[model.InterfaceID]string{},
	}
}

func (o *orchestrator) admin(fn func(tx store.Tx) error) bool {
	if !o.w.cp.up {
		return false
	}
	_, err := o.w.cp.update(fn)
	return err == nil
}

func (o *orchestrator) setup() {
	w, now := o.w, o.w.now()
	for _, r := range w.relays {
		o.admin(func(tx store.Tx) error {
			rec, _, err := w.cp.plane.CreateRelay(tx, now, api.CreateRelay{
				Name: r.name, Addresses: []api.RelayAddress{r.address()}, PortLo: 10000, PortHi: 10999, ProbePort: relayProbePort,
			})
			r.id = rec.ID
			return err
		})
	}
	for _, h := range w.hosts {
		o.admin(func(tx store.Tx) error {
			rec, _, err := w.cp.plane.CreateHost(tx, now, cp.Global(), api.CreateHost{Name: h.name})
			h.id = rec.ID
			return err
		})
	}
	for i := range w.opts.Networks {
		n := &netIntent{name: fmt.Sprintf("net%d", i), rules: map[model.RuleID]store.Rule{}}
		relays := make([]model.RelayID, len(w.relays))
		for j, r := range w.relays {
			relays[j] = r.id
		}
		for j := len(relays) - 1; j > 0; j-- {
			k := o.rng.Index(j + 1)
			relays[j], relays[k] = relays[k], relays[j]
		}
		// Every network uses the same prefixes, so overlapping address
		// spaces are the norm.
		req := api.CreateNetwork{
			Name: n.name, Relays: relays,
			Prefix6: netip.MustParsePrefix("fd00:5d4e::/64"), Prefix4: w.opts.Prefix4,
		}
		o.admin(func(tx store.Tx) error {
			rec, err := w.cp.plane.CreateNetwork(tx, now, req)
			n.id = rec.ID
			return err
		})
		for j := range w.opts.Services {
			s := &svcIntent{name: fmt.Sprintf("s%d", j), ipv4: o.rng.Percent(uint64(w.opts.IPv4Percent))}
			mode := api.Flip
			if o.rng.Percent(uint64(w.opts.CutoverPercent)) {
				mode = api.Cutover
			}
			o.admin(func(tx store.Tx) error {
				rec, err := w.cp.plane.CreateService(tx, now, cp.Global(), string(n.id), api.CreateService{Name: s.name, IPv4: s.ipv4, Mode: mode})
				s.id, s.addr6, s.addr4 = rec.ID, rec.Addr6, rec.Addr4
				return err
			})
			n.services = append(n.services, s)
		}
		o.networks = append(o.networks, n)
		for _, a := range n.services {
			for _, b := range n.services {
				if o.rng.Percent(uint64(w.opts.RulePercent)) {
					o.addRule(n, a, b)
				}
			}
		}
		o.record(n)
	}
}

func (o *orchestrator) randomRule() (model.Proto, model.PortRange) {
	switch o.rng.Below(4) {
	case 0:
		return model.AnyProto, model.PortRange{}
	case 1:
		return model.UDP, model.PortRange{Lo: 53, Hi: 53}
	default:
		p := uint16(80 + o.rng.Below(3)*1000)
		return model.TCP, model.PortRange{Lo: p, Hi: p}
	}
}

// grantEgress sometimes lets a service reach the internet, or takes a grant
// away.
func (o *orchestrator) grantEgress() {
	if !o.egress.Percent(4) || len(o.networks) == 0 {
		return
	}
	n := o.networks[o.egress.Index(len(o.networks))]
	var grants []model.RuleID
	for _, id := range sortedKeys(n.rules) {
		if n.rules[id].To == "" {
			grants = append(grants, id)
		}
	}
	if len(grants) > 0 && o.egress.Percent(40) {
		id := grants[o.egress.Index(len(grants))]
		if o.admin(func(tx store.Tx) error { return o.w.cp.plane.DeleteRule(tx, o.w.now(), cp.Global(), string(n.id), id) }) {
			delete(n.rules, id)
			o.record(n)
		}
		return
	}
	s := n.services[o.egress.Index(len(n.services))]
	proto, ports := model.TCP, model.PortRange{Lo: 443, Hi: 443}
	if o.egress.Percent(30) {
		proto, ports = model.UDP, model.PortRange{Lo: 53, Hi: 53}
	}
	var r store.Rule
	if o.admin(func(tx store.Tx) error {
		var err error
		r, err = o.w.cp.plane.CreateRule(tx, o.w.now(), cp.Global(), string(n.id), api.CreateRule{From: string(s.id), To: api.Internet, Proto: proto, Ports: ports})
		return err
	}) {
		n.rules[r.ID] = r
		o.w.summary.EgressGrants++
		o.record(n)
	}
}

// changePolicy sometimes adds a wildcard or deny rule, toward a service or
// the internet, or takes one away.
func (o *orchestrator) changePolicy() {
	if !o.policy.Percent(6) || len(o.networks) == 0 {
		return
	}
	n := o.networks[o.policy.Index(len(o.networks))]
	var drawn []model.RuleID
	for _, id := range sortedKeys(n.rules) {
		if r := n.rules[id]; r.Deny || r.From == model.AnyService || r.To == model.AnyService {
			drawn = append(drawn, id)
		}
	}
	if len(drawn) > 0 && o.policy.Percent(40) {
		id := drawn[o.policy.Index(len(drawn))]
		if o.admin(func(tx store.Tx) error { return o.w.cp.plane.DeleteRule(tx, o.w.now(), cp.Global(), string(n.id), id) }) {
			delete(n.rules, id)
			o.w.summary.Policies++
			o.record(n)
		}
		return
	}
	side := func() string {
		if o.policy.Percent(40) {
			return api.Wildcard
		}
		return string(n.services[o.policy.Index(len(n.services))].id)
	}
	req := api.CreateRule{From: side(), To: side()}
	if o.policy.Percent(15) {
		req.To = api.Internet
	}
	// An allow names every service on some side, so each rule drawn here
	// is a wildcard or a deny.
	if o.policy.Percent(55) {
		req.Action = api.Deny
	} else if req.From != api.Wildcard && req.To != api.Wildcard {
		req.From = api.Wildcard
	}
	switch o.policy.Below(6) {
	case 0:
		req.Proto = model.AnyProto
	case 1:
		req.Proto, req.Ports = model.UDP, model.PortRange{Lo: 53, Hi: 53}
	case 2:
		req.Proto, req.Ports = model.TCP, model.PortRange{Lo: 1, Hi: 1500}
	case 3:
		req.Proto, req.Ports = model.TCP, model.PortRange{Lo: 1000, Hi: 3000}
	default:
		p := uint16(80 + o.policy.Below(3)*1000)
		req.Proto, req.Ports = model.TCP, model.PortRange{Lo: p, Hi: p}
	}
	if req.To == api.Internet && req.Proto == model.TCP {
		req.Ports = model.PortRange{Lo: 443, Hi: 443}
	}
	var r store.Rule
	if o.admin(func(tx store.Tx) error {
		var err error
		r, err = o.w.cp.plane.CreateRule(tx, o.w.now(), cp.Global(), string(n.id), req)
		return err
	}) {
		n.rules[r.ID] = r
		o.w.summary.Policies++
		o.record(n)
	}
}

func (o *orchestrator) addRule(n *netIntent, a, b *svcIntent) {
	proto, ports := o.randomRule()
	var r store.Rule
	if o.admin(func(tx store.Tx) error {
		var err error
		r, err = o.w.cp.plane.CreateRule(tx, o.w.now(), cp.Global(), string(n.id), api.CreateRule{From: string(a.id), To: string(b.id), Proto: proto, Ports: ports})
		return err
	}) {
		n.rules[r.ID] = r
		o.w.summary.Rules++
		o.record(n)
	}
}

// record appends the network's current rules to its ledger at the
// network's current revision.
func (o *orchestrator) record(n *netIntent) {
	var rev uint64
	o.w.cp.view(func(tx store.ReadTx) error {
		rec, err := tx.Network(n.id)
		rev = rec.Revision
		return err
	})
	rules := make([]store.Rule, 0, len(n.rules))
	for _, id := range sortedKeys(n.rules) {
		rules = append(rules, n.rules[id])
	}
	n.history = append(n.history, ruleSet{revision: rev, rules: rules})
}

// rulesAt returns a network's rules as of a revision.
func (n *netIntent) rulesAt(rev uint64) []store.Rule {
	i, _ := slices.BinarySearchFunc(n.history, rev, func(rs ruleSet, r uint64) int {
		switch {
		case rs.revision < r:
			return -1
		case rs.revision > r:
			return 1
		}
		return 0
	})
	if i < len(n.history) && n.history[i].revision == rev {
		return n.history[i].rules
	}
	if i == 0 {
		return nil
	}
	return n.history[i-1].rules
}

func (o *orchestrator) network(id model.NetworkID) *netIntent {
	for _, n := range o.networks {
		if n.id == id {
			return n
		}
	}
	return nil
}

func (o *orchestrator) start() {
	o.running = true
	var next func()
	next = func() {
		if !o.running {
			return
		}
		o.change()
		o.grantEgress()
		o.changePolicy()
		o.attachMember()
		o.changeScope()
		o.w.loop.After(o.rng.Duration(o.w.opts.ChangeEvery/4, o.w.opts.ChangeEvery*2), next)
	}
	o.w.loop.After(o.w.opts.ChangeEvery, next)
}

func (o *orchestrator) stop() { o.running = false }

func (o *orchestrator) live() []*ifIntent {
	var out []*ifIntent
	for _, id := range sortedKeys(o.ifaces) {
		if i := o.ifaces[id]; i.state == attached {
			out = append(out, i)
		}
	}
	return out
}

func (o *orchestrator) change() {
	live := o.live()
	switch r := o.rng.Below(100); {
	case r < 40:
		if len(live)+len(o.attaching) < o.w.opts.MaxAttached {
			o.attach()
		}
	case r < 65:
		if len(live) > 0 {
			o.detach(live[o.rng.Index(len(live))])
		}
	case r < 70:
		if len(live) > 0 {
			o.revoke(live[o.rng.Index(len(live))])
		}
	case r < 85:
		n := o.networks[o.rng.Index(len(o.networks))]
		o.addRule(n, n.services[o.rng.Index(len(n.services))], n.services[o.rng.Index(len(n.services))])
	default:
		n := o.networks[o.rng.Index(len(o.networks))]
		ids := sortedKeys(n.rules)
		if len(ids) == 0 {
			return
		}
		id := ids[o.rng.Index(len(ids))]
		if o.admin(func(tx store.Tx) error { return o.w.cp.plane.DeleteRule(tx, o.w.now(), cp.Global(), string(n.id), id) }) {
			delete(n.rules, id)
			o.w.summary.Rules++
			o.record(n)
		}
	}
}

func (o *orchestrator) attach() {
	n := o.networks[o.rng.Index(len(o.networks))]
	o.names++
	p := &pendingAttach{
		name: fmt.Sprintf("w%d", o.names), net: n,
		svc: n.services[o.rng.Index(len(n.services))], host: o.w.hosts[o.rng.Index(len(o.w.hosts))],
	}
	o.attaching[p.name] = p
	o.tryAttach(p)
}

// memberNames is how many names the orchestrator draws a service's
// members from: m0, m1 and so on.
const memberNames = 3

// attachMember sometimes attaches a workload holding a member name, as an
// orchestrator running a cluster would, more often than not replacing
// whoever holds it.
func (o *orchestrator) attachMember() {
	if !o.member.Percent(10) || len(o.live())+len(o.attaching) >= o.w.opts.MaxAttached {
		return
	}
	n := o.networks[o.member.Index(len(o.networks))]
	o.names++
	p := &pendingAttach{
		name: fmt.Sprintf("w%d", o.names), net: n,
		svc: n.services[o.member.Index(len(n.services))], host: o.w.hosts[o.member.Index(len(o.w.hosts))],
		member: fmt.Sprintf("m%d", o.member.Index(memberNames)), replace: o.member.Percent(60),
	}
	o.attaching[p.name] = p
	o.tryAttach(p)
}

// tryAttach asks the agent for the workload's interface. An agent that
// crashed before answering may have built it, so a retry names the same
// workload and gets the interface already built.
func (o *orchestrator) tryAttach(p *pendingAttach) {
	h := p.host
	retry := func() { o.w.loop.After(retryAfter, func() { o.tryAttach(p) }) }
	a := api.LocalAttach{Name: p.name, Network: p.net.name, Service: p.svc.name, Member: p.member, Replace: p.replace}
	ok := h.localAttach(a, func(li api.LocalInterface, err error) {
		if o.attaching[p.name] != p {
			return
		}
		if errors.Is(err, agentcore.ErrAttachFailed) {
			o.w.logf("attach of %s on %s failed: %v", p.name, h.name, err)
			var ae *api.Error
			if p.member != "" && errors.As(err, &ae) && ae.Code == api.CodeConflict {
				o.w.summary.MemberConflicts++
			}
			delete(o.attaching, p.name)
			return
		}
		if err != nil {
			retry()
			return
		}
		delete(o.attaching, p.name)
		o.w.summary.Attaches++
		x := &ifIntent{
			id: li.Interface, network: li.Network, service: li.Service, host: h, ns: li.Namespace,
			addr6: li.Addr6, addr4: li.Addr4, key: li.PublicKey, state: attached, member: p.member,
		}
		o.ifaces[x.id] = x
		if p.member != "" {
			o.requested[x.id] = p.member
			o.w.summary.Members++
		}
		o.w.byKey[x.key] = x.id
		o.w.logf("attached %s as %s on %s (%v %v)", p.name, x.id, h.name, x.addr6, x.addr4)
		if h.kernel.Hold(x.ns) {
			x.held, _ = h.kernel.Named(x.ns)
		}
		o.work(x)
	})
	if !ok {
		retry()
	}
}

func (o *orchestrator) detach(x *ifIntent) {
	x.state = detachingState
	o.tryDetach(x)
}

// tryDetach asks until the agent answers; one that no longer holds the
// interface finished an earlier attempt.
func (o *orchestrator) tryDetach(x *ifIntent) {
	if o.ifaces[x.id] != x {
		return
	}
	retry := func() { o.w.loop.After(retryAfter, func() { o.tryDetach(x) }) }
	ok := x.host.localDetach(x.id, func(_ api.LocalInterface, err error) {
		if o.ifaces[x.id] != x {
			return
		}
		if err != nil && !errors.Is(err, agentcore.ErrNoInterface) {
			retry()
			return
		}
		o.w.summary.Detaches++
		o.w.logf("detached %s", x.id)
		o.gone(x, o.w.faultsOn && o.w.opts.StrayPermille > 0 && o.rng.Permille(o.w.opts.StrayPermille))
	})
	if !ok {
		retry()
	}
}

// gone ends a workload. A stray process may keep its namespace held, as an
// orphaned iperf3 would.
func (o *orchestrator) gone(x *ifIntent, stray bool) {
	delete(o.ifaces, x.id)
	if x.held == nil {
		return
	}
	if stray {
		o.w.summary.Strays++
		o.w.logf("a stray process keeps %s's namespace", x.id)
		return
	}
	x.host.kernel.Unhold(x.held)
	x.held = nil
}

// unname deletes the name of a workload's namespace while the workload
// still holds it, as an operator's `ip netns del` would. The interface is
// lost: its agent must notice, release it, and reap the device left in the
// held namespace. The workload exits a while later.
func (o *orchestrator) unname(h *hostNode) {
	var held []*ifIntent
	for _, id := range sortedKeys(o.ifaces) {
		if x := o.ifaces[id]; x.host == h && x.state == attached && x.held != nil {
			held = append(held, x)
		}
	}
	if len(held) == 0 {
		return
	}
	x := held[o.unnamer.Index(len(held))]
	h.kernel.Unname(x.ns)
	h.unnamed[x.ns] = true
	o.w.summary.Unnamed++
	o.w.logf("an operator deletes %s's namespace name while its workload holds it", x.id)
	delete(o.ifaces, x.id)
	ns := x.held
	x.held = nil
	o.w.loop.After(o.unnamer.Duration(time.Second, 20*time.Second), func() { h.kernel.Unhold(ns) })
}

// changeScope sometimes changes which networks a host may attach into, as
// an operator handing a host to a tenant would: every network, a subset, or
// none. The host's interfaces in the networks it loses are revoked, and the
// orchestrator's attaches outside its scope are refused.
func (o *orchestrator) changeScope() {
	if !o.scope.Percent(5) {
		return
	}
	h := o.w.hosts[o.scope.Index(len(o.w.hosts))]
	sc := api.Scope{Global: o.scope.Percent(40)}
	if !sc.Global {
		for _, n := range o.networks {
			if o.scope.Percent(60) {
				sc.Networks = append(sc.Networks, n.name)
			}
		}
	}
	if o.admin(func(tx store.Tx) error {
		_, _, err := o.w.cp.plane.SetHostScope(tx, o.w.now(), cp.Global(), h.name, sc)
		return err
	}) {
		o.w.summary.Rescopes++
		o.w.logf("host %s scoped to %+v", h.name, sc)
	}
}

func (o *orchestrator) revoke(x *ifIntent) {
	if o.admin(func(tx store.Tx) error { return o.w.cp.plane.Revoke(tx, o.w.now(), x.id) }) {
		o.w.summary.Revokes++
		o.w.logf("revoked %s", x.id)
	}
}

// hostLost forgets every workload on a host that rebooted.
func (o *orchestrator) hostLost(h *hostNode) {
	for _, id := range sortedKeys(o.ifaces) {
		if x := o.ifaces[id]; x.host == h {
			x.held = nil
			delete(o.ifaces, id)
		}
	}
}

// work runs a workload's traffic: connections to services its policy
// reaches, and to anything else in reach of a typo.
func (o *orchestrator) work(x *ifIntent) {
	var tick func()
	tick = func() {
		if o.ifaces[x.id] != x || x.state != attached || !o.w.faultsOn {
			return
		}
		n := o.network(x.network)
		if n != nil {
			s := n.services[o.w.work.Index(len(n.services))]
			proto, ports := o.randomRule()
			port := ports.Lo
			if proto == model.AnyProto {
				proto, port = model.TCP, 80
			}
			dst := s.addr6
			if x.addr4.IsValid() && s.addr4.IsValid() && o.w.work.Percent(50) {
				dst = s.addr4
			}
			f := o.w.open(x, dst, proto, port)
			x.flows = append(x.flows, f)
			if len(x.flows) > 8 {
				x.flows = x.flows[1:]
			}
			for _, old := range x.flows {
				if old != f && old.state == established {
					o.w.sendData(old)
				}
			}
		}
		o.w.loop.After(o.w.work.Duration(200*time.Millisecond, time.Second), tick)
	}
	o.w.loop.After(o.w.work.Duration(0, time.Second), tick)
}
