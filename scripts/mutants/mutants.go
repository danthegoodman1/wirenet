package main

// Files the mutants edit.
const (
	agentCore    = "internal/agent/core/core.go"
	agentLife    = "internal/agent/core/lifecycle.go"
	agentPlan    = "internal/agent/core/plan.go"
	agentTarget  = "internal/agent/core/target.go"
	agentRelays  = "internal/agent/core/relays.go"
	agentDaemon  = "internal/agent/daemon/daemon.go"
	agentResolv  = "internal/agent/resolver/resolver.go"
	agentMain    = "cmd/wirenet-agent/main.go"
	agentUnder   = "internal/agent/underlay/underlay.go"
	linuxEgress  = "internal/kernel/linux/egress.go"
	linuxNetns   = "internal/kernel/linux/netns.go"
	nftTx        = "internal/nft/tx.go"
	compileGo    = "internal/compile/compile.go"
	cpAlloc      = "internal/cp/alloc.go"
	cpEdges      = "internal/cp/edges.go"
	cpPlane      = "internal/cp/plane.go"
	cpCensus     = "internal/cp/census.go"
	cpServer     = "internal/cpserver/server.go"
	apiState     = "internal/api/state.go"
	pgTx         = "internal/store/pgstore/tx.go"
	cpHub        = "internal/cpserver/hub.go"
	linuxKernel  = "internal/kernel/linux/linux.go"
	linuxNFT     = "internal/kernel/linux/nftables.go"
	nftGo        = "internal/nft/nft.go"
	regprotoGo   = "internal/regproto/regproto.go"
	relayCore    = "internal/relay/core/core.go"
	relayServer  = "internal/relay/server/server.go"
	relayDisk    = "internal/relay/server/disk.go"
	simCP        = "internal/sim/cpnode.go"
	kmodelGo     = "internal/kernel/kmodel/kmodel.go"
	modelWeight  = "internal/model/relayweight.go"
	modelGo      = "internal/model/model.go"
	policyGo     = "internal/compile/policy.go"
	agentFDStore = "internal/agent/resolver/fdstore.go"
	dnsGo        = "internal/dns/dns.go"
	memStore     = "internal/store/mem/mem.go"
	pgQueries    = "internal/store/pgstore/db/interfaces.sql.go"
	pgScopes     = "internal/store/pgstore/schema/0007_scopes.sql"
	storeGo      = "internal/store/store.go"
	cpScope      = "internal/cp/scope.go"
	cpState      = "internal/cp/state.go"
	cpHandlers   = "internal/cpserver/handlers.go"
	cpclientGo   = "internal/cpclient/client.go"
	cpLimits     = "internal/cpserver/limits.go"
)

// Code that more than one edit moves or matches.
const (
	// relayDataOld is the relay's check that a data packet comes from its
	// direction's registered endpoint.
	relayDataOld = "if !d.Endpoint.IsValid() || src != d.Endpoint {"
	// applyRules is the agent's nftables transaction within a batch.
	applyRules = "\tif tx := nft.Diff(st.rules, tgt.rules); !tx.Empty() {\n\t\tops = append(ops, kernel.Op{Kind: kernel.ApplyRules, Namespace: st.name, Rules: &tx})\n\t}\n"
	// removeUnwanted opens the agent's loop over installed peers the target
	// drops.
	removeUnwanted = "\tfor _, key := range slices.SortedFunc(maps.Keys(st.peers), compareKey) {\n\t\tif want[key] {\n"
	// destroyFlushed is the kernel's destruction of a flush's sockets.
	destroyFlushed = "n, err := h.diag.destroyMatching(func(s sock) bool {\n\t\treturn cm.carried[flowTuple{s.proto, s.local, s.remote}] || !sweep && match(s.remote.Addr())\n\t})"
	// appendLog is the relay committer's write of registrations to its log.
	appendLog = "\t\t\tif err := s.disk.Append(batch); err != nil {\n\t\t\t\treturn fmt.Errorf(\"registration log: %w\", err)\n\t\t\t}\n"
)

// Mutants are the planted bugs, one per behavior SPEC.md and CLAUDE.md name.
var Mutants = []Mutant{
	{
		ID:     "slot-map-partial",
		Breaks: "every slot of a service's map carries a backend; a missed lookup leaves the packet addressed to the service",
		Edits:  []Edit{{agentTarget, "for slot, i := range table {", "for slot, i := range table[:len(table)-1] {"}},
		Catch:  []string{"sim"},
	},
	{
		ID:     "slot-map-unchecked",
		Breaks: "a slot map shorter than the slot count validates, so nftables would accept a map a lookup can miss",
		Edits:  []Edit{{nftGo, "if len(m.Slots) != Slots {", "if len(m.Slots) > Slots {"}},
		Catch:  []string{"nft"},
	},
	{
		ID:     "numgen-inc",
		Breaks: "slots are drawn with numgen random; numgen inc starts every client namespace on slot 0",
		Edits:  []Edit{{linuxNFT, "Type: unix.NFT_NG_RANDOM", "Type: unix.NFT_NG_INCREMENTAL"}},
		Catch:  []string{"kernel"},
	},
	{
		ID:     "keepalive-both-sides",
		Breaks: "exactly one side of a co-located pair arms persistent-keepalive",
		Edits:  []Edit{{compileGo, "p.Keepalive = keepsAlive(x, y, links)", "p.Keepalive = true"}},
		Catch:  []string{"cp", "sim"},
	},
	{
		ID:     "keepalive-armed-before-reverse",
		Breaks: "a co-located peer's keepalive is armed only once the other device holds the reverse peer, so its first initiation is never dropped",
		Edits:  []Edit{{agentTarget, "(tp.awaiting || p.Draining)", "p.Draining"}},
		Catch:  []string{"sim"},
	},
	{
		ID:     "slot-before-colocated-reverse",
		Breaks: "no slot names a co-located backend until its device holds the reverse peer, so a client's first initiation is never dropped",
		Edits:  []Edit{{agentTarget, "if !p.peer.Draining && !p.awaiting {", "if !p.peer.Draining {"}},
		Catch:  []string{"sim"},
	},
	{
		ID:     "keepalive-on-relay-peers",
		Breaks: "relay peers carry no persistent-keepalive; the registration datagram holds the NAT mapping",
		Edits:  []Edit{{compileGo, "\tp.Registration = e.SecretAB\n", "\tp.Registration, p.Keepalive = e.SecretAB, true\n"}},
		Catch:  []string{"cp", "sim"},
	},
	{
		ID:     "relay-forwards-race-loser",
		Breaks: "a packet from anywhere but the direction's registered endpoint, such as one that lost an endpoint race, is dropped",
		Edits:  []Edit{{relayCore, relayDataOld, "if !d.Endpoint.IsValid() {"}},
		Catch:  []string{"relay-core", "relay-server"},
	},
	{
		ID:     "relay-data-moves-endpoint",
		Breaks: "only a verified registration moves a relay endpoint; a data packet never does",
		Edits:  []Edit{{relayCore, relayDataOld, "if d.Endpoint.IsValid() {\n\t\td.Endpoint = src\n\t}\n\t" + relayDataOld}},
		Catch:  []string{"relay-core", "relay-server", "sim"},
	},
	{
		ID:     "relay-replay-accepted",
		Breaks: "a registration whose counter does not exceed the highest accepted is a replay and fails",
		Edits:  []Edit{{relayCore, "if counter <= d.Counter {", "if counter < d.Counter {"}},
		Catch:  []string{"relay-core", "sim"},
	},
	{
		ID:     "registration-mac-skips-address",
		Breaks: "a registration's MAC covers the relay's advertised address and port, so one captured at one port or relay fails at another",
		Edits: []Edit{{regprotoGo,
			"\ta16 := advertised.Addr().As16()\n\tm.Write(a16[:])\n\tvar port [2]byte\n\tbinary.BigEndian.PutUint16(port[:], advertised.Port())\n\tm.Write(port[:])\n",
			"\t_ = advertised\n"}},
		Catch: []string{"regproto", "relay-core"},
	},
	{
		ID:     "relay-commit-ignores-key",
		Breaks: "a registration commits only under the key it verified under, so one made durable before its port was reallocated commits to nothing",
		Edits:  []Edit{{relayCore, "if !ok || r.Key != d.Key || r.Counter <= d.Counter {", "if !ok || r.Counter <= d.Counter {"}},
		Catch:  []string{"relay-core"},
	},
	{
		ID:     "relay-core-commits-on-verify",
		Breaks: "a verified registration moves no endpoint until the shell has made it durable and calls Commit",
		Edits:  []Edit{{relayCore, "return Decision{Verdict: Register, Registration: r}", "t.Commit(now, r)\n\t\treturn Decision{Verdict: Register, Registration: r}"}},
		Catch:  []string{"relay-core", "relay-server"},
	},
	{
		ID:     "relay-commits-before-durable",
		Breaks: "the relay commits a registration only once its log holds it, so a crash never forgets an endpoint it forwarded to",
		Edits: []Edit{
			{relayServer, appendLog, ""},
			{relayServer, "\t\t\tdirty = true\n", appendLog + "\t\t\tdirty = true\n"},
		},
		Catch: []string{"relay-server"},
	},
	{
		ID:     "agent-skips-flush",
		Breaks: "removing a peer flushes the conntrack entries and sockets addressed to it",
		Edits: []Edit{
			{agentPlan, "\t\tops = append(ops, kernel.Op{Kind: kernel.Flush, Namespace: st.name, Addrs: flush})\n", ""},
			{agentPlan,
				"\t\t\t\tfor _, a := range st.peers[u.PublicKey].Allowed {\n\t\t\t\t\tif !slices.Contains(st.unflushed, a.Addr()) {\n\t\t\t\t\t\tst.unflushed = append(st.unflushed, a.Addr())\n\t\t\t\t\t}\n\t\t\t\t}\n",
				""},
		},
		Catch: []string{"sim"},
	},
	{
		ID:     "flush-delays-registration",
		Breaks: "a batch that adds peers leaves the flush, which walks tables the whole host shares, to a later batch, so the peers register at once",
		Edits:  []Edit{{agentPlan, "later := len(adds) > 0 || len(ops) == 0 && len(st.awaiting) > 0", "later := len(ops) == 0 && len(st.awaiting) > 0"}},
		Catch:  []string{"agent-core"},
	},
	{
		ID:     "flush-ignores-waits",
		Breaks: "while a namespace waits on peers, a flush with nothing to follow waits too, so the batch that ends a wait opens the peers before it flushes",
		Edits:  []Edit{{agentPlan, "later := len(adds) > 0 || len(ops) == 0 && len(st.awaiting) > 0", "later := len(adds) > 0"}},
		Catch:  []string{"agent-core"},
	},
	{
		ID:     "flush-waits-forever",
		Breaks: "a flush waits on the namespace's waits for at most AckWait",
		Edits:  []Edit{{agentPlan, "\tcase later && now.Before(st.flushBy):\n", "\tcase later:\n"}},
		Catch:  []string{"agent-core"},
	},
	{
		ID:     "flush-starves-under-adds",
		Breaks: "a flush that batches adding peers leave to a later one runs once AckWait passes, though every batch adds",
		Edits:  []Edit{{agentPlan, "\tcase later && now.Before(st.flushBy):\n", "\tcase len(adds) > 0 || later && now.Before(st.flushBy):\n"}},
		Catch:  []string{"agent-core"},
	},
	{
		ID:     "leading-flush-keeps-deadline",
		Breaks: "a flush that leads a batch leaves the batch's own removals a wait of their own behind its new peers",
		Edits:  []Edit{{agentPlan, "\t\tst.flushBy = time.Time{}\n\t} else {\n", "\t} else {\n"}},
		Catch:  []string{"agent-core"},
	},
	{
		ID:     "unreached-peer-opened",
		Breaks: "a namespace opens only peers of the services it reaches, so a dial to another sends no handshake that could cross the peer's own",
		Edits:  []Edit{{agentTarget, "\t\t\tif reached[p.peer.Service] {\n", "\t\t\tif true {\n"}},
		Catch:  []string{"agent-core", "sim"},
	},
	{
		ID:     "wake-ignores-flush-wait",
		Breaks: "the core wakes when a flush's wait on the namespace's waits ends",
		Edits:  []Edit{{agentRelays, "\t\t\tif len(st.unflushed) > 0 && st.flushBy.After(now) {\n\t\t\t\tsoonest(st.flushBy)\n\t\t\t}\n", ""}},
		Catch:  []string{"agent-core"},
	},
	{
		ID:     "flush-leads-every-batch",
		Breaks: "a flush leads a batch only when the batch gives a peer an address it flushes, so the rules that open a peer go first",
		Edits:  []Edit{{agentPlan, "\tif claims {\n", "\tif claims || len(st.unflushed) > 0 {\n"}},
		Catch:  []string{"agent-core"},
	},
	{
		ID:     "claimed-address-flushed-after",
		Breaks: "a flush leads the batch that gives a peer an address it flushes, so no flow to the address outlives its old holder",
		Edits:  []Edit{{agentPlan, "\tif claims {\n", "\tif claims && false {\n"}},
		Catch:  []string{"sim"},
	},
	{
		ID:     "kernel-flush-skips-conntrack",
		Breaks: "a flush deletes the conntrack entries translated to a removed peer's address",
		Edits: []Edit{{linuxKernel,
			"n, err := h.nl.ConntrackDeleteFilters(netlink.ConntrackTable, family, cm)",
			"_ = family\n\t\tn, err := uint(0), error(nil)"}},
		Catch: []string{"kernel"},
	},
	{
		ID:     "kernel-flush-skips-socket-destroy",
		Breaks: "a flush destroys the sockets addressed to a removed peer (SOCK_DESTROY), since flushing conntrack leaves them",
		Edits:  []Edit{{linuxKernel, destroyFlushed, "n, err := 0, error(nil)"}},
		Catch:  []string{"kernel"},
	},
	{
		ID:     "kernel-flush-spares-translated-sockets",
		Breaks: "a flush destroys the sockets its conntrack entries carried, since a translated client's socket stays addressed to the service it dialed",
		Edits:  []Edit{{linuxKernel, "return cm.carried[flowTuple{s.proto, s.local, s.remote}] || !sweep && match(s.remote.Addr())", "return !sweep && match(s.remote.Addr())"}},
		Catch:  []string{"kernel"},
	},
	{
		ID:     "kernel-sweep-judges-dialed-address",
		Breaks: "a sweep judges a flow by the addresses its ends send from, so a connection through a live service survives it",
		Edits:  []Edit{{linuxKernel, "\tif !c.senders {\n", "\tif true {\n"}},
		Catch:  []string{"kernel"},
	},
	{
		ID:     "device-created-inside-namespace",
		Breaks: "a device is created from the host into the workload namespace, so its encrypted socket stays on the host",
		Edits:  []Edit{{linuxKernel, "if err := k.rootNL.LinkAdd(&netlink.Wireguard{LinkAttrs: attrs}); err != nil {", "if err := h.nl.LinkAdd(&netlink.Wireguard{LinkAttrs: attrs}); err != nil {"}},
		Catch:  []string{"kernel"},
	},
	{
		ID:     "revocation-drains",
		Breaks: "a revocation removes the interface from every peer at once, with no drain grace period",
		Edits:  []Edit{{cpPlane, "i.State, i.Drained = api.Revoked, true", "i.State, i.Drained = api.Released, false"}},
		Catch:  []string{"cp", "cpserver"},
	},
	{
		ID:     "peer-removed-before-slots",
		Breaks: "a batch removes a backend's slots before its peer, so no slot ever names an address without a peer",
		Edits: []Edit{
			{agentPlan, applyRules + removeUnwanted, removeUnwanted},
			{agentPlan, "\treturn ops\n}\n\n// sweep removes", applyRules + "\treturn ops\n}\n\n// sweep removes"},
		},
		Catch: []string{"sim"},
	},
	{
		ID:     "allowed-ip-moves",
		Breaks: "a peer claiming an address another installed peer holds waits until the holder is removed, so no allowed IP moves between peers",
		Edits:  []Edit{{agentTarget, "if conflicted(owner, p) {", "if false && conflicted(owner, p) {"}},
		Catch:  []string{"agent-core", "sim"},
	},
	{
		ID:     "ipv4-quarantine-from-release",
		Breaks: "an IPv4 address waits out its quarantine from its holder's drain, so a late drain never frees an address peers still route",
		Edits: []Edit{
			{cpPlane, "\t\ti.State, i.Ended = api.Released, now\n\t\tif _, err := p.end(tx, now, i, false); err != nil {", "\t\ti.State, i.Ended = api.Released, now\n\t\tif _, err := p.end(tx, now, i, true); err != nil {"},
			{cpPlane, "\t\tif i.Addr4.IsValid() {\n\t\t\tif err := tx.PutReleased4(store.Released4{Network: i.Network, Addr: i.Addr4, At: now}); err != nil {\n\t\t\t\treturn 0, err\n\t\t\t}\n\t\t}\n", ""},
		},
		Catch: []string{"cp"},
	},
	{
		ID:     "ipv4-quarantine-zero",
		Breaks: "a released IPv4 address waits out its quarantine before reuse",
		Edits:  []Edit{{cpAlloc, "free, err := tx.Released4(n.ID, now.Add(-p.Config.Quarantine4), 1)", "free, err := tx.Released4(n.ID, now, 1)"}},
		Catch:  []string{"cp", "sim"},
	},
	{
		ID:     "ipv6-reuse",
		Breaks: "an IPv6 address is never reused",
		Edits: []Edit{{cpPlane,
			"\tn, err := tx.Network(i.Network)\n\tif err != nil {\n\t\treturn holdings{}, err\n\t}\n\tvar held holdings\n",
			"\tn, err := tx.Network(i.Network)\n\tif err != nil {\n\t\treturn holdings{}, err\n\t}\n\tif n.Next6 > first6 && addrAt(n.Prefix6, n.Next6-1) == i.Addr6 {\n\t\tn.Next6--\n\t}\n\tvar held holdings\n"}},
		Catch: []string{"cp", "sim"},
	},
	{
		ID:     "expiry-ignores-boot-hold",
		Breaks: "after control-plane downtime, lease expiry waits at least as long as the outage lasted",
		Edits:  []Edit{{cpPlane, "if !now.Before(resumes) {", "if _ = resumes; true {"}},
		Catch:  []string{"cp"},
	},
	{
		ID:     "dormant-edge-deleted-at-once",
		Breaks: "an edge policy no longer connects stays dormant for the port quarantine before its ports free up",
		Edits:  []Edit{{cpEdges, "old, err := tx.DormantEdges(now.Add(-p.Config.PortQuarantine), limit)", "old, err := tx.DormantEdges(now, limit)"}},
		Catch:  []string{"cp"},
	},
	{
		ID:     "relay-port-reused-in-quarantine",
		Breaks: "a released relay port waits out its quarantine before it serves another edge",
		Edits:  []Edit{{cpAlloc, "free, err := tx.ReleasedPorts(r.ID, addr, now.Add(-p.Config.PortQuarantine), 1)", "free, err := tx.ReleasedPorts(r.ID, addr, now, 1)"}},
		Catch:  []string{"cp"},
	},
	{
		ID:     "agent-journals-private-key",
		Breaks: "the agent keeps a private key in the kernel device alone; no journal entry carries it",
		Edits: []Edit{
			{agentCore, "\tDetaching  bool              `json:\"detaching,omitempty\"`\n}", "\tDetaching  bool              `json:\"detaching,omitempty\"`\n\tPrivateKey model.Key `json:\"private_key\"`\n}"},
			{agentLife, "PublicKey: i.pub, Detaching: i.phase == detaching,", "PublicKey: i.pub, PrivateKey: i.priv, Detaching: i.phase == detaching,"},
			{agentPlan, "\t\ti.priv = model.Key{}\n\t\ti.phase, i.attachSent = registering, true", "\t\ti.phase, i.attachSent = registering, true"},
		},
		Catch: []string{"sim"},
	},
	{
		ID:     "hub-ignores-networks",
		Breaks: "a parked long poll wakes on a commit to any network its host holds, not only on one naming the host",
		Edits:  []Edit{{cpHub, "\tfor _, id := range c.Networks {\n\t\tfor w := range h.nets[id] {\n\t\t\twoken = append(woken, w)\n\t\t}\n\t}\n", ""}},
		Catch:  []string{"cpserver"},
	},
	{
		ID:     "sim-wake-ignores-networks",
		Breaks: "the simulator's control plane wakes a parked poll on a commit to a network its host holds, as the server's hub does",
		Edits: []Edit{{simCP,
			"if !slices.Contains(ch.Hosts, id) && !slices.ContainsFunc(p.nets, func(n model.NetworkID) bool { return slices.Contains(ch.Networks, n) }) {",
			"if !slices.Contains(ch.Hosts, id) {"}},
		Catch: []string{"sim"},
	},
	{
		ID:     "sweep-forgets-live-peers",
		Breaks: "a sweep keeps every flow an installed peer accounts for",
		Edits:  []Edit{{agentPlan, "for _, a := range installed[key].Allowed {", "for _, a := range installed[key].Allowed[:0] {"}},
		Catch:  []string{"sim"},
	},
	{
		ID:     "sweep-after-adds",
		Breaks: "a restart's sweep runs before the batch installs anything, so no flow a crash left to an address outlives a new peer's claim to it",
		Edits: []Edit{
			{agentPlan, "\tif st.sweep {\n\t\tops = append(ops, sweep(st.name, n, x, st.peers, ok))\n\t}\n", ""},
			{agentPlan, "\treturn ops\n}\n\n// sweep removes", "\tif st.sweep {\n\t\tops = append(ops, sweep(st.name, n, x, st.peers, ok))\n\t}\n\treturn ops\n}\n\n// sweep removes"},
		},
		Catch: []string{"agent-core"},
	},
	{
		ID:     "shrunk-peer-not-flushed",
		Breaks: "the addresses a peer drops, such as a machine a gateway stops fronting, are flushed like a removed peer's",
		Edits:  []Edit{{agentPlan, "\t\t\t\tfor _, a := range dropped {\n\t\t\t\t\tflush = append(flush, a.Addr())\n\t\t\t\t}\n", ""}},
		Catch:  []string{"agent-core"},
	},
	{
		ID:     "vanished-namespace-stays-ready",
		Breaks: "an interface whose namespace vanishes behind the agent is torn down, since its key went with the device",
		Edits:  []Edit{{agentLife, "\ti.phase = detaching\n\tc.emit(WriteJournal{Entry: c.entry(i)})\n\tfor _, name := range slices.Sorted(maps.Keys(c.ns)) {", "\tfor _, name := range slices.Sorted(maps.Keys(c.ns)) {"}},
		Catch:  []string{"agent-core", "sim"},
	},
	{
		ID:     "held-namespace-reaped-repeatedly",
		Breaks: "the agent reaps a namespace only a process holds once, then waits for the holder to let go",
		Edits:  []Edit{{agentPlan, "\t\tif st.reaped {\n\t\t\treturn nil\n\t\t}\n", ""}},
		Catch:  []string{"agent-core"},
	},
	{
		ID:     "moved-path-left-in-place",
		Breaks: "an edge whose relay leaves the set, or fails, moves its endpoint to the relay it now chooses",
		Edits:  []Edit{{agentPlan, "\t\tcase chosen != tp.endpoint:\n", "\t\tcase chosen != tp.endpoint && false:\n"}},
		Catch:  []string{"agent-core", "e2e"},
	},
	{
		ID:     "egress-filter-outlives-namespace",
		Breaks: "tearing down an interface whose namespace is gone still removes its host egress filter, by index",
		Edits:  []Edit{{agentPlan, "kernel.Op{Kind: kernel.SetEgress, Namespace: st.name, EgressIndex: egressIndex(st, i)}", "kernel.Op{Kind: kernel.SetEgress, Namespace: st.name}"}},
		Catch:  []string{"agent-core"},
	},
	{
		ID:     "gateway-end-spares-devices",
		Breaks: "releasing, revoking or expiring a gateway revokes its development machines at once",
		Edits:  []Edit{{cpPlane, "if i.Kind == api.Gateway {", "if false && i.Kind == api.Gateway {"}},
		Catch:  []string{"cp"},
	},
	{
		ID:     "device-fronted-from-any-host",
		Breaks: "a development machine is fronted only by its live gateway on that gateway's host",
		Edits:  []Edit{{compileGo, "i.State == api.Live && host == i.Host {", "i.State == api.Live && host != \"\" {"}},
		Catch:  []string{"cp"},
	},
	{
		ID:     "failed-update-changes-state",
		Breaks: "a host-state update that fails a check changes nothing",
		Edits:  []Edit{{apiState, "\tnext := make(map[model.NetworkID]*NetworkState, len(h.Networks))\n\tmaps.Copy(next, h.Networks)", "\tnext := h.Networks"}},
		Catch:  []string{"api"},
	},
	{
		ID:     "expiry-hold-needs-a-whole-term",
		Breaks: "a heartbeat more than a third of a lease term after the last holds off expiry for as long as the gap lasted",
		Edits:  []Edit{{cpPlane, "if gap <= p.Config.LeaseTTL/3 {", "if gap <= p.Config.LeaseTTL {"}},
		Catch:  []string{"cp"},
	},
	{
		ID:     "second-boot-shortens-hold",
		Breaks: "a boot or heartbeat only lengthens the expiry hold another replica set",
		Edits:  []Edit{{cpPlane, "if err != nil || !until.After(resumes) {", "if err != nil || !until.After(resumes) && false {"}},
		Catch:  []string{"cp"},
	},
	{
		ID:     "token-cached-forever",
		Breaks: "a cached host token expires after the token TTL, so a deleted host's token stops working on every replica",
		Edits:  []Edit{{cpServer, "ok && now.Before(c.(cachedToken).until) {", "ok {"}},
		Catch:  []string{"cpserver"},
	},
	{
		ID:     "host-deleted-with-live-interfaces",
		Breaks: "deleting a host revokes its interfaces",
		Edits:  []Edit{{cpPlane, "if err := p.Revoke(tx, now, i.ID); err != nil {\n\t\t\treturn store.Host{}, err", "if err := error(nil); err != nil && i.ID != \"\" {\n\t\t\treturn store.Host{}, err"}},
		Catch:  []string{"cp"},
	},
	{
		ID:     "store-error-answers-unauthorized",
		Breaks: "a token the store cannot check answers 503, which agents retry",
		Edits:  []Edit{{cpServer, "fmt.Errorf(\"token lookup: %w: %w\", errCannotAuthenticate, err)", "fmt.Errorf(\"token lookup: %w: %w\", errUnauthorized, err)"}},
		Catch:  []string{"cpserver"},
	},
	{
		ID:     "edge-toward-draining-interface",
		Breaks: "a draining interface keeps its edges but gains none",
		Edits:  []Edit{{cpEdges, "if have[key] || byID[key[0]].State != api.Live || byID[key[1]].State != api.Live {", "if have[key] {"}},
		Catch:  []string{"cp"},
	},
	{
		ID:     "host-releases-device",
		Breaks: "a development machine ends by revocation, its term or its gateway; its gateway's host cannot release it",
		Edits:  []Edit{{cpPlane, "if i.Host != host || i.State != api.Live || i.Kind == api.Device {\n\t\t\tcontinue\n\t\t}\n\t\ti.State, i.Ended", "if i.Host != host || i.State != api.Live {\n\t\t\tcontinue\n\t\t}\n\t\ti.State, i.Ended"}},
		Catch:  []string{"cp"},
	},
	{
		ID:     "network-delete-leaves-hosts",
		Breaks: "deleting a network moves its hosts' generations on, so their agents drop it",
		Edits:  []Edit{{cpPlane, "if err := bumpHosts(tx, slices.Compact(hosts)); err != nil {", "if err := bumpHosts(tx, nil); err != nil {"}},
		Catch:  []string{"cp"},
	},
	{
		ID:     "store-error-reads-as-not-found",
		Breaks: "a store error comes back as an error, never as a missing record",
		Edits:  []Edit{{cpPlane, "\t\treturn notFound(err, \"rule \"+string(id))", "\t\treturn notFound(store.ErrNotFound, \"rule \"+string(id))"}},
		Catch:  []string{"cp"},
	},
	{
		ID:     "port-quarantine-zero-accepted",
		Breaks: "the control plane refuses a zero port quarantine",
		Edits:  []Edit{{cpPlane, "case c.PortQuarantine <= 0:", "case c.PortQuarantine < 0:"}},
		Catch:  []string{"cp"},
	},
	{
		ID:     "census-misses-recent-ports",
		Breaks: "the census counts every relay port released within one quarantine",
		Edits:  []Edit{{cpCensus, "released, err := tx.ReleasedPorts(r.ID, a.Local, endOfTime(), 0)", "released, err := tx.ReleasedPorts(r.ID, a.Local, now, 0)"}},
		Catch:  []string{"cp"},
	},
	{
		ID:     "relay-wait-scans-every-port",
		Breaks: "each port counts its own waiting packets, so admitting one costs the same however many wait",
		Edits:  []Edit{{relayCore, "\tif t.held >= t.cfg.WaitTotal || len(d.waits) >= t.cfg.WaitMax {", "\tcount := 0\n\tfor w := t.oldest; w != nil; w = w.next {\n\t\tif w.local == d.Local {\n\t\t\tcount++\n\t\t}\n\t}\n\tif t.held >= t.cfg.WaitTotal || count >= t.cfg.WaitMax {"}},
		Catch:  []string{"relay-core"},
	},
	{
		ID:     "relay-release-scans-every-port",
		Breaks: "a commit looks only at the ports it touches",
		Edits:  []Edit{{relayCore, "\tfor _, local := range t.touched {", "\tfor _, local := range slices.SortedFunc(maps.Keys(t.ports), netip.AddrPort.Compare) {"}},
		Catch:  []string{"relay-core"},
	},
	{
		ID:     "relay-forwards-truncated",
		Breaks: "the relay drops a datagram the kernel truncated rather than forward a prefix",
		Edits:  []Edit{{relayServer, "if rms[i].Flags&unix.MSG_TRUNC != 0 {", "if false {"}},
		Catch:  []string{"relay-server"},
	},
	{
		ID:     "relay-bind-never-retried",
		Breaks: "a port that fails to bind is retried every few seconds while the other ports serve",
		Edits:  []Edit{{relayServer, "\t\tcase <-retry.C:\n\t\t\tif !failed {\n\t\t\t\tcontinue\n\t\t\t}\n", "\t\tcase <-retry.C:\n\t\t\tcontinue\n"}},
		Catch:  []string{"relay-server"},
	},
	{
		ID:     "relay-commits-under-unsaved-table",
		Breaks: "a registration verified under a table the state file lacks writes that table first",
		Edits:  []Edit{{relayServer, "if s.generation() != s.durable {", "if false {"}},
		Catch:  []string{"relay-server"},
	},
	{
		ID:     "relay-log-keeps-torn-tail",
		Breaks: "opening the registration log cuts a torn last line, so the next append starts a fresh one",
		Edits:  []Edit{{relayDisk, "\tif n < len(b) {", "\tif false {"}},
		Catch:  []string{"relay-server"},
	},
	{
		ID:     "relay-junk-spends-owner-budget",
		Breaks: "only a verified registration spends a port's budget, so junk cannot lock its owner out",
		Edits:  []Edit{{relayCore, "\tr, reason := t.verify(d, src, b)\n", "\td.regs.spend()\n\tr, reason := t.verify(d, src, b)\n"}},
		Catch:  []string{"relay-core"},
	},
	{
		ID:     "relay-holds-unknown-ports",
		Breaks: "a packet for a port the table lacks drops",
		Edits:  []Edit{{relayCore, "\t\treturn Decision{Reason: Unknown}", "\t\treturn Decision{Verdict: Wait, Reason: Unknown}"}},
		Catch:  []string{"relay-core"},
	},
	{
		ID:     "relay-probes-uncapped",
		Breaks: "the probe port answers a bounded number of probes a second across the relay, since a probe's source can be forged",
		Edits:  []Edit{{relayCore, "if !p.b.take(now) {", "if false {"}},
		Catch:  []string{"relay-core"},
	},
	{
		ID:     "pgstore-relay-delete-keeps-ports",
		Breaks: "deleting a relay deletes its released ports and cursors, so a relay created under the same ID starts with none",
		Edits:  []Edit{{pgTx, "\tif err := t.check(t.q.DeleteRelayPorts(t.ctx, string(id))); err != nil {\n\t\treturn err\n\t}\n", ""}},
		Catch:  []string{"pgstore"},
	},
	{
		ID:     "attach-answered-before-resolver",
		Breaks: "an attach is answered once its namespace's stub resolver listens, so a workload that resolves at start is answered",
		Edits:  []Edit{{agentDaemon, "if d.Resolver != nil && a.Err == nil && a.Interface.Ready {", "if false {"}},
		Catch:  []string{"agent-daemon"},
	},
	{
		ID:     "resolver-forwards-inline",
		Breaks: "a forwarded query waits off the read loop, so a slow upstream delays no local answer",
		Edits:  []Edit{{agentResolv, "\t\tgo func() {\n\t\t\tdefer func() { <-forwards }()", "\t\tfunc() {\n\t\t\tdefer func() { <-forwards }()"}},
		Catch:  []string{"agent-resolver"},
	},
	{
		ID:     "resolver-tcp-uncapped",
		Breaks: "each namespace's resolver holds a bounded number of TCP connections",
		Edits:  []Edit{{agentResolv, "conns := make(chan struct{}, tcpConns)", "conns := make(chan struct{}, 1<<20)"}},
		Catch:  []string{"agent-resolver"},
	},
	{
		ID:     "egress-refresh-not-retried",
		Breaks: "a failed egress filter refresh retries until it succeeds or a newer set replaces it",
		Edits:  []Edit{{agentDaemon, "retry = time.After(d.cfg.EgressRetry)", "_ = d.cfg.EgressRetry"}},
		Catch:  []string{"agent-daemon"},
	},
	{
		ID:     "egress-ignores-host-change",
		Breaks: "an underlay change refreshes the egress filter with the host's current prefixes",
		Edits:  []Edit{{agentDaemon, "\t\t\t\td.egressRelays = d.EgressKept\n\t\t\t}\n\t\t\td.refreshEgress()\n", "\t\t\t\td.egressRelays = d.EgressKept\n\t\t\t}\n"}},
		Catch:  []string{"agent-daemon"},
	},
	{
		ID:     "underlay-drops-trailing-change",
		Breaks: "an underlay change inside the throttle window runs when the window ends, so the address the host settles on registers",
		Edits:  []Edit{{agentMain, "\t\t\t\tdue = time.After(wait)\n", ""}},
		Catch:  []string{"agent-cmd"},
	},
	{
		ID:     "egress-nat64-unblocked",
		Breaks: "an egress link cannot reach a blocked IPv4 address through its NAT64 form",
		Edits:  []Edit{{linuxEgress, "\t\tout = append(out, netip.PrefixFrom(netip.AddrFrom16(b), 96+p.Bits()))", "\t\t_ = b"}},
		Catch:  []string{"kernel"},
	},
	{
		ID:     "egress-filter-forgets-blocked",
		Breaks: "the egress filter records what it blocks, so a restarted agent keeps blocking every relay it knew of",
		Edits:  []Edit{{linuxEgress, "\t\t\tUserData: comment(blockedTag + p.String())})", "\t\t})"}},
		Catch:  []string{"kernel"},
	},
	{
		ID:     "held-by-descriptor-missed",
		Breaks: "a namespace only a descriptor holds is found and reaped",
		Edits:  []Edit{{linuxNetns, "if onNSFS(path, self.Dev) && isNetNS(path) {", "if onNSFS(path, self.Dev) && isNetNS(path) && false {"}},
		Catch:  []string{"kernel"},
	},
	{
		ID:     "unmounted-name-accepted",
		Breaks: "a namespace name a crash left as a plain file is replaced by a mounted namespace",
		Edits:  []Edit{{linuxNetns, "\tcase err == nil && mounted:\n", "\tcase err == nil && (mounted || true):\n"}},
		Catch:  []string{"kernel"},
	},
	{
		ID:     "nft-model-deletes-missing-element",
		Breaks: "the model fails a transaction deleting a missing set element, as the kernel fails the batch",
		Edits:  []Edit{{nftTx, "\t\t\tif !slices.Contains(s.Addrs, a) {\n\t\t\t\treturn nil, fmt.Errorf(\"%w: set %s element %v\", ErrMissing, e.Set, a)", "\t\t\tif false {\n\t\t\t\treturn nil, fmt.Errorf(\"%w: set %s element %v\", ErrMissing, e.Set, a)"}},
		Catch:  []string{"nft"},
	},
	{
		ID:     "metric-increment-dropped",
		Breaks: "every local attach and detach counts in wirenet_agent_local_calls_total by result",
		Edits:  []Edit{{agentDaemon, "\td.m.localCalls.WithLabelValues(r.kind, result).Inc()\n", "\t_ = result\n"}},
		Catch:  []string{"agent-daemon", "e2e"},
	},
	{
		ID:     "census-gauges-stale",
		Breaks: "the agent's interface, namespace and peer gauges follow the core's census",
		Edits:  []Edit{{agentDaemon, "\t\td.m.census(c)\n", "\t\t_ = c\n"}},
		Catch:  []string{"agent-daemon"},
	},
	{
		ID:     "relay-sends-no-ack",
		Breaks: "a relay acknowledges each registration it commits, from the direction's port, so an agent knows the port is bound",
		Edits:  []Edit{{relayServer, "\t\t\ts.ack(acked)\n", ""}},
		Catch:  []string{"relay-server"},
	},
	{
		ID:     "new-relay-peer-slotted-before-ack",
		Breaks: "no slot names a relay peer new to a namespace until the active relay acknowledges it, or AckWait passes",
		Edits:  []Edit{{agentTarget, "tp.awaiting = c.awaitsAck(now, st, port, p, tp)", "tp.awaiting = false && c.awaitsAck(now, st, port, p, tp)"}},
		Catch:  []string{"agent-core"},
	},
	{
		ID:     "handover-ignores-waiting-slots",
		Breaks: "a namespace is handed over only once the slots it holds back are in, or AckWait passes",
		Edits:  []Edit{{agentPlan, "if len(st.awaiting) > 0 && now.Before(i.handoverBy) {", "if false {"}},
		Catch:  []string{"agent-core"},
	},
	{
		ID:     "ack-releases-nothing",
		Breaks: "a relay's acknowledgment releases the wait of the peer it names",
		Edits:  []Edit{{agentRelays, "\t\t\tw.acked = true\n", ""}},
		Catch:  []string{"agent-core"},
	},
	{
		ID:     "failover-holds-slots-back",
		Breaks: "a peer installed before never waits for an acknowledgment, so a failover holds back no slot",
		Edits:  []Edit{{agentTarget, "\tif !ok {\n\t\tif _, installed := st.peers[p.PublicKey]; installed {\n\t\t\treturn false\n\t\t}\n\t\tw = &ackWait{", "\tif !ok {\n\t\tw = &ackWait{"}},
		Catch:  []string{"agent-core"},
	},
	{
		ID:     "ack-filter-reads-the-wrong-word",
		Breaks: "the agent's raw IPv4 socket passes relay acknowledgments, judged past the IP header's own length",
		Edits:  []Edit{{agentUnder, "{Code: unix.BPF_LD | unix.BPF_W | unix.BPF_IND, K: 8},", "{Code: unix.BPF_LD | unix.BPF_W | unix.BPF_IND, K: 12},"}},
		Catch:  []string{"underlay"},
	},
	{
		ID:     "registration-never-resent",
		Breaks: "a fresh direction's registration is sent again on a tripling schedule, since one that beats the relay's bind is lost",
		Edits:  []Edit{{agentRelays, "r.left, r.gap, r.after = c.cfg.RegisterRetries, c.cfg.RegisterRetry, floor", "r.left, r.gap, r.after = 0, c.cfg.RegisterRetry, floor"}},
		Catch:  []string{"agent-core"},
	},
	{
		ID:     "relay-drops-what-races-the-peer",
		Breaks: "a packet that reaches a bound port before the peer direction registers waits for that registration instead of dropping",
		Edits:  []Edit{{relayCore, "if ok && t.wait(now, d, src, b) {", "if false && t.wait(now, d, src, b) {"}},
		Catch:  []string{"relay-core"},
	},
	{
		ID:     "acked-direction-resent",
		Breaks: "a relay's acknowledgment ends that direction's resends to it, so registrations stay bounded under churn",
		Edits:  []Edit{{agentRelays, "\t\t\tdelete(r.paths, from)\n", ""}},
		Catch:  []string{"agent-core"},
	},
	{
		ID:     "rearm-replans-everyone",
		Breaks: "a finished batch replans only the namespaces waiting on its device, so waits on acknowledgments cost nothing per batch",
		Edits: []Edit{{agentPlan, "\tfor _, name := range slices.Sorted(maps.Keys(c.reverseWait[changed.iface])) {\n\t\tif st, ok := c.ns[name]; ok && st != changed {\n",
			"\tfor _, name := range slices.Sorted(maps.Keys(c.ns)) {\n\t\tif st, ok := c.ns[name]; ok && st != changed && len(st.awaiting) > 0 {\n"}},
		Catch: []string{"agent-core"},
	},
	{
		ID:     "backend-hands-over-before-relay",
		Breaks: "a backend's attach answers once the relay holds its edges' ports, though no slot of its own names its clients",
		Edits:  []Edit{{agentTarget, "\t\t\tdefault:\n\t\t\t\t// A peer no slot names holds nothing back", "\t\t\tcase len(x.Reach) > 0:\n\t\t\t\t// A peer no slot names holds nothing back"}},
		Catch:  []string{"agent-core"},
	},
	{
		ID:     "unawaited-ack-reports-change",
		Breaks: "an acknowledgment nobody awaits changes nothing, so the agent's loop skips its pass over every namespace",
		Edits:  []Edit{{agentRelays, "\tname, ok := c.awaitingAck[key]\n\tif !ok {\n\t\treturn changed\n\t}\n", "\tname, ok := c.awaitingAck[key]\n\tif !ok {\n\t\treturn true\n\t}\n"}},
		Catch:  []string{"agent-core"},
	},
	{
		ID:     "stale-ack-wake-spins",
		Breaks: "a network that leaves desired state takes its acknowledgment waits with it, so no past deadline keeps waking the loop",
		Edits:  []Edit{{agentPlan, "\t} else {\n\t\tc.dropWaits(st)\n", "\t} else {\n"}},
		Catch:  []string{"agent-core"},
	},
	{
		ID:     "resend-forgets-its-port",
		Breaks: "a resend schedule ends with its namespace, so acknowledgment lookups stay bounded",
		Edits:  []Edit{{agentRelays, "delete(c.resendAck, ackKey{r.paths[path], path})", "delete(c.resendAck, ackKey{0, path})"}},
		Catch:  []string{"agent-core"},
	},
	{
		ID:     "convergence-only-after-batches",
		Breaks: "convergence is observed whenever a namespace settles, batch or no batch",
		Edits:  []Edit{{agentDaemon, "\tidle := d.core.Stats.Idle != d.stats.Idle\n", "\tidle := false\n"}},
		Catch:  []string{"agent-daemon"},
	},
	{
		ID:     "underlay-change-drops-kept-filter",
		Breaks: "an underlay change before desired state keeps blocking the relays an earlier run's filter named",
		Edits:  []Edit{{agentDaemon, "\t\t\tif !d.egressSent {\n\t\t\t\td.egressRelays = d.EgressKept\n\t\t\t}\n", ""}},
		Catch:  []string{"agent-daemon"},
	},
	{
		ID:     "agent-sockets-hold-nothing",
		Breaks: "the agent's sockets hold a namespace its name no longer reaches, so its device keeps its peers until the agent tears it down",
		Edits:  []Edit{{kmodelGo, "\tif ns.Held == 0 && ns.opened == \"\" && ns.Name == \"\" && k.anon[ns.Ref] == ns {", "\tif ns.Held == 0 && ns.Name == \"\" && k.anon[ns.Ref] == ns {"}},
		Catch:  []string{"kmodel"},
	},
	{
		ID:     "cached-handle-trusted",
		Breaks: "every open checks the namespace's name still reaches it, which is how the agent learns an operator deleted it",
		Edits: []Edit{{linuxKernel, "\tpath := filepath.Join(netnsDir, name)\n\tvar st unix.Stat_t\n",
			"\tpath := filepath.Join(netnsDir, name)\n\tif h, ok := k.handles[name]; ok {\n\t\treturn h, nil\n\t}\n\tvar st unix.Stat_t\n"}},
		Catch: []string{"kernel"},
	},
	{
		ID:     "egress-duplicates-kept",
		Breaks: "refreshing the egress filter from what it holds leaves one rule per prefix",
		Edits:  []Edit{{linuxEgress, "\treturn slices.Compact(kernel.SortPrefixes(all))\n", "\treturn all\n"}},
		Catch:  []string{"kernel"},
	},
	{
		ID:     "relay-weight-one-sided",
		Breaks: "both ends of an edge weigh a relay the same, so they choose the same relay",
		Edits:  []Edit{{modelWeight, "\tif b < a {\n\t\ta, b = b, a\n\t}\n", ""}},
		Catch:  []string{"model", "e2e"},
	},
	{
		ID:     "relay-chosen-per-network",
		Breaks: "each edge chooses its relay by its own weight, so a network's edges spread over its relays",
		Edits:  []Edit{{agentRelays, "w := model.RelayWeight(self, p.Interface, rp.Relay)", "w := model.RelayWeight(\"\", \"\", rp.Relay)"}},
		Catch:  []string{"agent-core", "e2e"},
	},
	{
		ID:     "relay-choice-ignores-health",
		Breaks: "an edge sends through a relay its agent's probes find up",
		Edits:  []Edit{{agentRelays, "\t\tup := !probed || h.up\n", "\t\tup := !probed || h.up || true\n"}},
		Catch:  []string{"agent-core", "e2e"},
	},
	{
		ID:     "relay-loss-not-replanned",
		Breaks: "a relay's loss moves the edges it carried",
		Edits:  []Edit{{agentRelays, "\tif len(down) > 0 {\n\t\tc.relaysChanged(down)\n\t}\n", ""}},
		Catch:  []string{"agent-core", "e2e"},
	},
	{
		ID:     "relay-return-not-replanned",
		Breaks: "a relay that answers again takes back the edges whose heaviest relay it is",
		Edits:  []Edit{{agentRelays, "\t\th.up = true\n\t\tc.relaysChanged(map[model.RelayID]bool{relay: true})\n", "\t\th.up = true\n"}},
		Catch:  []string{"agent-core"},
	},
	{
		ID:     "detach-releases-after-teardown",
		Breaks: "a detach tells the control plane while its device is deleted, so peers stop routing to it without waiting out the deletion",
		Edits:  []Edit{{agentLife, "\t// deleting a device waits a grace period per peer it holds.\n\tc.release(i)\n", "\t// deleting a device waits a grace period per peer it holds.\n"}},
		Catch:  []string{"agent-core"},
	},
	{
		ID:     "release-retry-waits-for-teardown",
		Breaks: "a detach's failed release is sent again while its teardown runs",
		Edits:  []Edit{{agentLife, "if (i.tornDown || i.phase == detaching) && i.attachSent", "if i.tornDown && i.attachSent"}},
		Catch:  []string{"agent-core"},
	},
	{
		ID:     "stored-socket-made-blocking",
		Breaks: "a resolver socket handed to the descriptor store stays non-blocking, so closing it on detach returns",
		Edits: []Edit{{agentFDStore, "\tif err := rc.Control(func(fd uintptr) {\n\t\tserr = unix.Sendmsg(s.fd, []byte(msg), unix.UnixRights(int(fd)), s.addr, 0)\n\t}); err != nil {\n\t\treturn err\n\t}\n",
			"\tif f, ok := c.(interface{ File() (*os.File, error) }); ok {\n\t\tif file, err := f.File(); err == nil {\n\t\t\tdefer file.Close()\n\t\t\tserr = unix.Sendmsg(s.fd, []byte(msg), unix.UnixRights(int(file.Fd())), s.addr, 0)\n\t\t}\n\t}\n\t_ = rc\n"}},
		Catch: []string{"agent-resolver", "e2e"},
	},
	{
		ID:     "wildcard-reaches-its-own-service",
		Breaks: "a wildcard destination never matches the service on the rule's other side",
		Edits:  []Edit{{policyGo, "\t\t\t\tif to != from {\n", "\t\t\t\tif true {\n"}},
		Catch:  []string{"compile", "cp", "sim", "e2e"},
	},
	{
		ID:     "wildcard-source-reaches-its-own-service",
		Breaks: "a wildcard source never matches the service on the rule's other side",
		Edits:  []Edit{{policyGo, "case has(r.To) && (r.From != model.AnyService || r.To != from):", "case has(r.To):"}},
		Catch:  []string{"compile", "sim"},
	},
	{
		ID:     "deny-ignored",
		Breaks: "a deny takes the flows it names out of every allow",
		Edits:  []Edit{{policyGo, "\t\t\tif names(r, p.from, p.to) {", "\t\t\tif false && names(r, p.from, p.to) {"}},
		Catch:  []string{"compile", "cp", "cpserver", "sim", "e2e"},
	},
	{
		ID:     "wildcard-deny-matches-its-own-service",
		Breaks: "a wildcard deny spares a service's rule naming itself on both sides",
		Edits:  []Edit{{policyGo, "return s == self || s == model.AnyService && self != other }", "return s == self || s == model.AnyService }"}},
		Catch:  []string{"compile", "sim"},
	},
	{
		ID:     "egress-deny-ignored",
		Breaks: "a deny toward the internet takes egress back",
		Edits:  []Edit{{policyGo, "\t\treturn r.To == \"\" && (r.From == from || r.From == model.AnyService)\n", "\t\treturn false\n"}},
		Catch:  []string{"compile", "sim"},
	},
	{
		ID:     "port-deny-takes-the-protocol",
		Breaks: "a deny of some TCP ports leaves the allow's other TCP ports",
		Edits:  []Edit{{policyGo, "\t\tf.tcp = f.tcp.remove(spanOf(ports))", "\t\tf.tcp = nil"}},
		Catch:  []string{"compile", "sim", "e2e"},
	},
	{
		ID:     "adjacent-ranges-kept-apart",
		Breaks: "allows whose port ranges touch merge into one grant",
		Edits:  []Edit{{policyGo, "case x.hi+1 < n.lo || n.hi+1 < x.lo:", "case x.hi < n.lo || n.hi < x.lo:"}},
		Catch:  []string{"compile"},
	},
	{
		ID:     "other-protocols-dropped",
		Breaks: "a deny that takes TCP or UDP out of an allow for any protocol leaves every other protocol open",
		Edits:  []Edit{{policyGo, "\tif f.other {\n\t\tout = append(out, Grant{From: from, To: to, Proto: model.OtherProto})\n\t}\n", ""}},
		Catch:  []string{"compile", "sim", "e2e"},
	},
	{
		ID:     "other-protocols-admit-tcp",
		Breaks: "a grant for other protocols admits neither TCP nor UDP",
		Edits:  []Edit{{modelGo, "\t\treturn proto != TCP && proto != UDP\n", "\t\treturn true\n"}},
		Catch:  []string{"model", "compile", "sim"},
	},
	{
		ID:     "linux-other-protocols-admit-everything",
		Breaks: "nftables matches the other-protocols grant as anything but TCP and UDP",
		Edits:  []Edit{{linuxNFT, "\tcase model.AnyProto:\n\t\treturn nil\n\tcase model.OtherProto:", "\tcase model.AnyProto, model.OtherProto:\n\t\treturn nil\n\tcase \"none\":"}},
		Catch:  []string{"kernel", "e2e"},
	},
	{
		ID:     "wildcard-rule-reconciles-one-pair",
		Breaks: "a rule whose source is every service reconciles the edges of every pair with its destination",
		Edits:  []Edit{{cpEdges, "\t\treturn serviceScope(r.To)\n", "\t\treturn servicesScope(r.From, r.To)\n"}},
		Catch:  []string{"cp", "sim"},
	},
	{
		ID:     "rule-deduplicated-across-actions",
		Breaks: "an allow and a deny of the same flows are two rules",
		Edits:  []Edit{{cpPlane, " && r.Ports == req.Ports && r.Deny == deny {", " && r.Ports == req.Ports {"}},
		Catch:  []string{"cp"},
	},
	{
		ID:     "pgstore-forgets-deny",
		Breaks: "Postgres keeps whether a rule denies",
		Edits:  []Edit{{pgTx, "Created: r.Created,\n\t\tDeny: r.Deny,\n\t}))", "Created: r.Created,\n\t}))"}},
		Catch:  []string{"pgstore"},
	},
	{
		ID:     "keepalive-on-the-reached-side",
		Breaks: "the side of a co-located pair that reaches the other keeps alive",
		Edits:  []Edit{{compileGo, "\tif xy != yx {\n\t\treturn xy\n\t}", "\tif xy != yx {\n\t\treturn yx\n\t}"}},
		Catch:  []string{"cp", "sim"},
	},
	{
		ID:     "keepalive-ignores-fronted",
		Breaks: "a gateway whose development machines reach a co-located peer keeps the pair alive",
		Edits:  []Edit{{compileGo, "xy, yx := links.Opens(x, y), links.Opens(y, x)", "xy, yx := links.adj.Reaches(x.Service, y.Service), links.adj.Reaches(y.Service, x.Service)"}},
		Catch:  []string{"cp"},
	},
	{
		ID:     "keepalive-counts-shielded-flows",
		Breaks: "flows into a gateway's development machines, which its shield turns away, never choose the keepalive side",
		Edits:  []Edit{{compileGo, "xy, yx := links.Opens(x, y), links.Opens(y, x)", "xy, yx := links.Reaches(x, y), links.Reaches(y, x)"}},
		Catch:  []string{"cp"},
	},
	{
		ID:     "denied-service-unrejected",
		Breaks: "a namespace rejects the services no interface on its host reaches, so a deny leaves no untranslated flow",
		Edits:  []Edit{{agentTarget, "\tothers := slices.Clone(n.Unreached)\n", "\tvar others []netip.Addr\n"}},
		Catch:  []string{"agent-core"},
	},
	{
		ID:     "unreached-services-unsent",
		Breaks: "a host learns the addresses of the services none of its interfaces reach",
		Edits:  []Edit{{compileGo, "\t\t\t\t\tns.Unreached = append(ns.Unreached, a)\n", ""}},
		Catch:  []string{"cp"},
	},
	{
		ID:     "scan-deletes-no-name",
		Breaks: "an interface whose device a scan finds elsewhere deletes its namespace's name, which may still stand",
		Edits:  []Edit{{agentLife, "\tst.device, st.egress = false, nil\n", "\tst.exists, st.device, st.egress = false, false, nil\n"}},
		Catch:  []string{"agent-core"},
	},
	{
		ID:     "session-deadline-before-reverse",
		Breaks: "a session wait's deadline starts once the other device holds the reverse peer",
		Edits:  []Edit{{agentTarget, "\tif held && w.until.IsZero() {\n", "\tif w.until.IsZero() {\n"}},
		Catch:  []string{"agent-core"},
	},
	{
		ID:     "failed-session-check-keeps-waiting",
		Breaks: "a session check that fails ends the wait instead of asking again at once",
		Edits:  []Edit{{agentTarget, "\t\tfor _, key := range slices.SortedFunc(maps.Keys(st.sessions), compareKey) {\n\t\t\tst.sessions[key].up = true\n\t\t}\n", ""}},
		Catch:  []string{"agent-core"},
	},
	{
		ID:     "scan-keeps-unnamed-peer",
		Breaks: "a scan that finds a held interface's device where only a process holds it drops that namespace's peers, so co-located clients stop slotting it",
		Edits:  []Edit{{agentLife, "\t\t\tif named, ok := c.ns[i.ns]; ok {\n\t\t\t\tc.lost(named)\n", "\t\t\tif named, ok := c.ns[i.ns]; ok && false {\n\t\t\t\tc.lost(named)\n"}},
		Catch:  []string{"agent-core"},
	},
	{
		ID:     "lost-peer-leaves-clients-planned",
		Breaks: "a namespace whose co-located peer is lost replans at once",
		Edits:  []Edit{{agentLife, "\t\t\tc.ns[name].dirty = true\n", ""}},
		Catch:  []string{"agent-core"},
	},
	{
		ID:     "session-wait-skipped",
		Breaks: "the side of a co-located pair without keepalive slots its peer once it holds a session",
		Edits:  []Edit{{agentTarget, "\tif p.Keepalive || !slices.ContainsFunc(x.Reach,", "\tif true || p.Keepalive || !slices.ContainsFunc(x.Reach,"}},
		Catch:  []string{"agent-core"},
	},
	{
		ID:     "waiting-peer-opened",
		Breaks: "a peer takes new flows at its own address only once a slot may name it, so a dial to a member's name sends no initiation a wait holds back",
		Edits:  []Edit{{agentTarget, "\t\t\tif !live[p.peer.Interface] {\n", "\t\t\tif p.peer.Draining {\n"}},
		Catch:  []string{"agent-core", "sim"},
	},
	{
		ID:     "draining-peer-opened",
		Breaks: "a draining peer takes no new flow at its own address",
		Edits:  []Edit{{agentTarget, "\t\t\tif !live[p.peer.Interface] {\n", "\t\t\tif p.awaiting {\n"}},
		Catch:  []string{"sim"},
	},
	{
		ID:     "own-address-closed",
		Breaks: "a namespace's own addresses stay open to its new flows",
		Edits:  []Edit{{agentTarget, "for _, a := range x.Addrs() {", "for _, a := range x.Addrs()[:0] {"}},
		Catch:  []string{"agent-core", "sim"},
	},
	{
		ID:     "open-rule-unwritten",
		Breaks: "a namespace rejects a new flow into the network's prefixes that its open set lacks",
		Edits:  []Edit{{linuxNFT, "for _, o := range r.Open {", "for _, o := range r.Open[:0] {"}},
		Catch:  []string{"kernel"},
	},
	{
		ID:     "open-rule-refuses-replies",
		Breaks: "the open set holds back new flows alone; a reply to a closed address passes",
		Edits:  []Edit{{linuxNFT, "match := append(family(f), ctState(expr.CtStateBitNEW)...)", "match := family(f)"}},
		Catch:  []string{"kernel"},
	},
	{
		ID:     "open-rule-inverted",
		Breaks: "a new flow goes to an address the open set holds, and only to one",
		Edits:  []Edit{{linuxNFT, "SetName: set.Name, SetID: set.ID, Invert: true})", "SetName: set.Name, SetID: set.ID})"}},
		Catch:  []string{"kernel"},
	},
	{
		ID:     "closed-beyond-the-prefix",
		Breaks: "the open set governs the network's prefixes alone; an address beyond them is never closed",
		Edits:  []Edit{{nftTx, "\t\tif !o.Prefix.Contains(dst) {\n\t\t\tcontinue\n\t\t}\n", ""}},
		Catch:  []string{"nft"},
	},
	{
		ID:     "sessions-read-without-handshake",
		Breaks: "a device reads as holding a session only once a handshake completes",
		Edits:  []Edit{{linuxKernel, "\t\t\tif !p.LastHandshakeTime.IsZero() {\n\t\t\t\tr.Sessions", "\t\t\tif true {\n\t\t\t\tr.Sessions"}},
		Catch:  []string{"kernel"},
	},
	{
		ID:     "relay-reload-resets-counter",
		Breaks: "a reload keeps an unchanged port's counter, so a registration from before it stays a replay",
		Edits:  []Edit{{relayCore, "d.Endpoint, d.Counter, d.Stats = old.Endpoint, old.Counter, old.Stats", "d.Endpoint, d.Stats = old.Endpoint, old.Stats"}},
		Catch:  []string{"relay-core"},
	},
	{
		ID:     "withdrawal-unsent",
		Breaks: "an agent withdraws a relay peer's direction once neither its desired state nor its device holds the peer",
		Edits:  []Edit{{agentRelays, "\tc.withdrawGone(now, st)\n", ""}},
		Catch:  []string{"agent-core"},
	},
	{
		ID:     "withdrawal-untracked",
		Breaks: "an agent keeps what a relay peer's registrations take until the peer is gone",
		Edits:  []Edit{{agentPlan, "\t\tc.track(now, st, x)\n", ""}},
		Catch:  []string{"agent-core"},
	},
	{
		ID:     "withdrawal-claims",
		Breaks: "a withdrawal carries kind 1",
		Edits:  []Edit{{regprotoGo, "return encode(key, advertised, counter, withdraw)", "return encode(key, advertised, counter, claim)"}},
		Catch:  []string{"regproto", "relay-core", "agent-core"},
	},
	{
		ID:     "registration-unknown-kind",
		Breaks: "a relay verifies only kinds 0 and 1",
		Edits:  []Edit{{regprotoGo, "b[5] > withdraw || ", ""}},
		Catch:  []string{"regproto"},
	},
	{
		ID:     "relay-reads-withdrawal-as-claim",
		Breaks: "a relay reads a verified withdrawal as one",
		Edits:  []Edit{{relayCore, "Key: d.Key, Withdraw: withdraw}", "Key: d.Key}"}},
		Catch:  []string{"relay-core"},
	},
	{
		ID:     "withdrawal-keeps-endpoint",
		Breaks: "a committed withdrawal clears the direction's endpoint",
		Edits:  []Edit{{relayCore, "\t\td.Endpoint = netip.AddrPort{}\n\t\treturn true\n", "\t\treturn true\n"}},
		Catch:  []string{"relay-core"},
	},
	{
		ID:     "named-peer-withdrawn",
		Breaks: "a relay peer the desired state still names keeps its direction, installed or not",
		Edits:  []Edit{{agentRelays, "if _, installed := st.peers[key]; r.named || installed {", "if _, installed := st.peers[key]; installed {"}},
		Catch:  []string{"agent-core"},
	},
	{
		ID:     "changed-secret-unclaimed",
		Breaks: "an installed relay peer whose secret or relay ports change claims at once",
		Edits:  []Edit{{agentRelays, "\t\tif _, installed := st.peers[p.PublicKey]; known && installed {\n\t\t\tst.fresh[p.PublicKey] = true\n", "\t\tif _, installed := st.peers[p.PublicKey]; known && installed {\n"}},
		Catch:  []string{"agent-core"},
	},
	{
		ID:     "withdrawal-resend-unscheduled",
		Breaks: "the agent wakes when its earliest withdrawal is due again",
		Edits:  []Edit{{agentRelays, "\t\t\t\tif c.nextWithdrawal.IsZero() || w.at.Before(c.nextWithdrawal) {\n\t\t\t\t\tc.nextWithdrawal = w.at\n\t\t\t\t}\n", ""}},
		Catch:  []string{"agent-core"},
	},
	{
		ID:     "withdrawal-ack-replans",
		Breaks: "a withdrawal's acknowledgment asks for no pass over the namespaces",
		Edits:  []Edit{{agentRelays, "\t\tdelete(c.withdrawals, key)\n\t}\n\tif ref, ok", "\t\tdelete(c.withdrawals, key)\n\t\tchanged = true\n\t}\n\tif ref, ok"}},
		Catch:  []string{"agent-core"},
	},
	{
		ID:     "resent-withdrawal-unanswered",
		Breaks: "a relay acknowledges a resent copy of the withdrawal it holds",
		Edits:  []Edit{{relayCore, "if withdraw && counter == d.Counter && !d.Endpoint.IsValid() {", "if false {"}},
		Catch:  []string{"relay-core"},
	},
	{
		ID:     "resent-withdrawal-spends-rejects",
		Breaks: "a resent withdrawal spends its port's registration budget, never the relay-wide reject budget",
		Edits:  []Edit{{relayCore, "\tcase Duplicate:\n\t\td.regs.spend()\n", "\tcase Duplicate:\n\t\tt.rejects.spend()\n"}},
		Catch:  []string{"relay-core"},
	},
	{
		ID:     "withdrawal-not-resent",
		Breaks: "a withdrawal goes again until its relay acknowledges it",
		Edits:  []Edit{{agentRelays, "\tc.resendWithdrawals(now)\n", ""}},
		Catch:  []string{"agent-core"},
	},
	{
		ID:     "withdrawal-ends-on-any-ack",
		Breaks: "only an acknowledgment of a withdrawal's own counter ends its resends",
		Edits:  []Edit{{agentRelays, "if w, ok := c.withdrawals[key]; ok && w.counter == counter {", "if _, ok := c.withdrawals[key]; ok {"}},
		Catch:  []string{"agent-core"},
	},
	{
		ID:     "withdrawal-outlives-claim",
		Breaks: "a claim ends the resends of the withdrawal it outranks",
		Edits:  []Edit{{agentRelays, "\t\t\tdelete(c.withdrawals, ackKey{i.port, rp.Send})\n", ""}},
		Catch:  []string{"agent-core"},
	},
	{
		ID:     "slot-on-withdrawal-ack",
		Breaks: "a relay peer back after its withdrawal takes its slot only once the relay acknowledges a claim made for it",
		Edits:  []Edit{{agentRelays, "w.path == from && !w.acked && counter > w.after", "w.path == from && !w.acked"}},
		Catch:  []string{"agent-core"},
	},
	{
		ID:     "claim-resend-ends-on-old-ack",
		Breaks: "only an acknowledgment of a claim the schedule sent ends its resends",
		Edits:  []Edit{{agentRelays, "if scheduled && counter > r.after {", "if scheduled {"}},
		Catch:  []string{"agent-core"},
	},
	{
		ID:     "egress-grant-unrecorded",
		Breaks: "an egress grant reads back whole from its chain, however many flows it holds",
		Edits:  []Edit{{linuxEgress, ",\n\t\t\tUserData: comment(grantTag + formatRule(r))})", "})"}},
		Catch:  []string{"kernel"},
	},
	{
		ID:     "unrecorded-grant-fails-observation",
		Breaks: "a grant chain that records no flow reads as an empty grant, which the agent rewrites",
		Edits:  []Edit{{linuxEgress, "\t\tif !ok || err != nil {\n\t\t\treturn nil, nil\n", "\t\tif !ok || err != nil {\n\t\t\treturn nil, fmt.Errorf(\"rule %d records %q\", r.Handle, r.UserData)\n"}},
		Catch:  []string{"kernel"},
	},
	{
		ID:     "egress-records-bare-text",
		Breaks: "nft shows what an egress rule records as its comment",
		Edits:  []Edit{{linuxEgress, "func comment(s string) []byte { return userdata.AppendString(nil, userdata.TypeComment, s) }", "func comment(s string) []byte { _ = userdata.TypeComment; return []byte(s) }"}},
		Catch:  []string{"kernel"},
	},
	{
		ID:     "service-scope-pairs-twice",
		Breaks: "a wildcard rule's scope lists each pair within its service once",
		Edits:  []Edit{{cpEdges, "case j == i || j < i && y.Service == s.service:", "case j == i:"}},
		Catch:  []string{"cp"},
	},
	{
		ID:     "member-conflict-unchecked",
		Breaks: "an attach naming a held member fails with a conflict unless it replaces the holder",
		Edits:  []Edit{{cpPlane, "case !req.Replace:", "case false:"}},
		Catch:  []string{"cp", "e2e"},
	},
	{
		ID:     "replace-leaves-holder-live",
		Breaks: "a replacing attach revokes the member's holder in its own transaction",
		Edits:  []Edit{{cpPlane, "gone, err := p.revoke(tx, now, holder.ID)", "gone, err := holdings{}, error(nil)"}},
		Catch:  []string{"cp", "e2e"},
	},
	{
		ID:     "replace-drains-holder",
		Breaks: "a replaced holder is revoked, so it reaches no peer once hosts converge, rather than draining",
		Edits:  []Edit{{cpPlane, "gone, err := p.revoke(tx, now, holder.ID)", "gone, err := holdings{}, p.Release(tx, now, holder.Host, []model.InterfaceID{holder.ID})"}},
		Catch:  []string{"cp", "e2e"},
	},
	{
		ID:     "member-label-unchecked",
		Breaks: "a member name is a DNS label",
		Edits:  []Edit{{cpPlane, `req.Member != "" && (kind != api.Workload || !ValidName(req.Member))`, `req.Member != "" && kind != api.Workload`}},
		Catch:  []string{"cp"},
	},
	{
		ID:     "gateway-holds-member",
		Breaks: "only workloads hold member names",
		Edits:  []Edit{{cpPlane, `req.Member != "" && (kind != api.Workload || !ValidName(req.Member))`, `req.Member != "" && !ValidName(req.Member)`}},
		Catch:  []string{"cp"},
	},
	{
		ID:     "store-holder-counts-ended",
		Breaks: "an ended interface holds no member name, in the memory store",
		Edits:  []Edit{{memStore, `return member != "" && i.State == api.Live && i.Service == svc && i.Member == member`, `return member != "" && i.Service == svc && i.Member == member`}},
		Catch:  []string{"store", "cp"},
	},
	{
		ID:     "pg-holder-counts-ended",
		Breaks: "an ended interface holds no member name, in Postgres",
		Edits:  []Edit{{pgQueries, "WHERE service = $1 AND member = $2 AND state = 'live' AND member <> ''", "WHERE service = $1 AND member = $2 AND member <> ''"}},
		Catch:  []string{"pgstore"},
	},
	{
		ID:     "backend-name-unset",
		Breaks: "a client's state names each member it reaches",
		Edits:  []Edit{{compileGo, "Interface: i.ID, Addr6: i.Addr6, Addr4: i.Addr4, Name: memberName(i, services),", "Interface: i.ID, Addr6: i.Addr6, Addr4: i.Addr4,"}},
		Catch:  []string{"cp", "sim", "e2e"},
	},
	{
		ID:     "own-name-unset",
		Breaks: "a member's own state carries its name",
		Edits:  []Edit{{compileGo, "Name:       memberName(x, services),", ""}},
		Catch:  []string{"cp", "sim", "e2e"},
	},
	{
		ID:     "ended-holder-keeps-name",
		Breaks: "an interface names itself only while it holds its name",
		Edits:  []Edit{{compileGo, `if i.Member == "" || i.State != api.Live || !ok {`, `if i.Member == "" || !ok {`}},
		Catch:  []string{"cp", "sim"},
	},
	{
		ID:     "zone-skips-members",
		Breaks: "a resolver answers the members of every service its interface reaches",
		Edits:  []Edit{{dnsGo, "\t\t\t\tadd(b.Name, b.Addr6, b.Addr4)\n", ""}},
		Catch:  []string{"dns", "sim", "e2e"},
	},
	{
		ID:     "zone-skips-own-name",
		Breaks: "a member's resolver answers its own name, whatever it reaches",
		Edits:  []Edit{{dnsGo, "\tif x.Name != \"\" {\n", "\tif false {\n"}},
		Catch:  []string{"dns", "sim"},
	},
	{
		ID:     "zone-a-for-ipv6-client",
		Breaks: "a client without IPv4 receives no A record, for a service or a member",
		Edits:  []Edit{{dnsGo, "if x.Addr4.IsValid() && addr4.IsValid() {", "if addr4.IsValid() {"}},
		Catch:  []string{"dns", "sim"},
	},
	{
		ID:     "name-above-member-missing",
		Breaks: "a name above a member's exists, with no records",
		Edits:  []Edit{{dnsGo, "if z.above(name) {", "if false {"}},
		Catch:  []string{"dns"},
	},
	{
		ID:     "retry-ignores-member",
		Breaks: "an attach retried under its interface's identifier returns the interface only for the member it holds",
		Edits:  []Edit{{cpPlane, "if existing.Member != req.Member {", "if false {"}},
		Catch:  []string{"cp"},
	},
	{
		ID:     "replace-without-member-accepted",
		Breaks: "a replacement names the member it takes over",
		Edits:  []Edit{{cpPlane, "if req.Replace && req.Member == \"\" {", "if false {"}},
		Catch:  []string{"cp"},
	},
	{
		ID:     "journal-drops-member",
		Breaks: "the agent's journal keeps an interface's member, so a restarted agent refuses to attach the workload as another",
		Edits:  []Edit{{agentLife, "Kind: i.kind, Member: i.member,", "Kind: i.kind,"}},
		Catch:  []string{"agent-core"},
	},
	{
		ID:     "observe-forgets-removal",
		Breaks: "a removal that failed partway still leaves the flows of the peers it took to flush",
		Edits:  []Edit{{agentPlan, "if !held[a] && !slices.Contains(st.unflushed, a.Addr()) {", "if false && !held[a] {"}},
		Catch:  []string{"agent-core"},
	},
	{
		ID:     "agent-drops-member",
		Breaks: "the agent asks the control plane for the member and replacement its caller named",
		Edits:  []Edit{{agentLife, "PublicKey: i.pub, ListenPort: i.port, Member: i.member, Replace: i.replace,", "PublicKey: i.pub, ListenPort: i.port,"}},
		Catch:  []string{"agent-core", "e2e"},
	},
	{
		ID:     "agent-ignores-member-change",
		Breaks: "a workload attached again keeps the member it holds",
		Edits:  []Edit{{agentLife, `if i.member != a.Member {`, `if false {`}},
		Catch:  []string{"agent-core"},
	},
	{
		ID:     "answer-omits-member-name",
		Breaks: "an attach answer names the member's full name",
		Edits:  []Edit{{agentLife, "\t\tif x.Name != \"\" {\n", "\t\tif false {\n"}},
		Catch:  []string{"agent-core", "e2e"},
	},
	{
		ID:     "crossed-initiation-forwarded",
		Breaks: "an initiation that crosses its peer's as the edge forms is dropped, so the two ends handshake once",
		Edits:  []Edit{{relayCore, "if kind == wgInitiation && t.crossed(now, d, peer) {", "if false {"}},
		Catch:  []string{"relay-core"},
	},
	{
		ID:     "held-initiations-released-together",
		Breaks: "of two directions' initiations one registration releases, only one goes",
		Edits:  []Edit{{relayCore, "if w.kind == wgInitiation && t.crossed(now, b.d, b.peer) {", "if false {"}},
		Catch:  []string{"relay-core", "e2e"},
	},
	{
		ID:     "held-initiations-unordered",
		Breaks: "of two directions' held initiations, the one that waited longer goes",
		Edits:  []Edit{{relayCore, "slices.SortStableFunc(batches, releaseOrder)", "slices.SortStableFunc(batches[:0], releaseOrder)"}},
		Catch:  []string{"relay-core"},
	},
	{
		ID:     "crossing-judged-always",
		Breaks: "the relay judges crossings only as a direction gains an endpoint, so a forged initiation suppresses the other end's that long at most",
		Edits:  []Edit{{relayCore, "(within(d.opened) || within(peer.opened)) && within(peer.initiated) &&", "within(peer.initiated) &&"}},
		Catch:  []string{"relay-core"},
	},
	{
		ID:     "answered-end-crosses",
		Breaks: "an initiation from an end that answered the peer's crosses nothing",
		Edits:  []Edit{{relayCore, "!d.answered.After(peer.initiated)", "true"}},
		Catch:  []string{"relay-core"},
	},
	{
		ID:     "response-unrecorded",
		Breaks: "the relay records a handshake response as its end answering",
		Edits:  []Edit{{relayCore, "k == wgInitiation && len(b) == 148, k == wgResponse && len(b) == 92, k == wgCookie", "k == wgInitiation && len(b) == 148, k == wgCookie"}},
		Catch:  []string{"relay-core"},
	},
	{
		ID:     "cookie-reply-unrecorded",
		Breaks: "the relay records a cookie reply as its end answering, since it leaves the end's own handshake whole",
		Edits:  []Edit{{relayCore, "\tcase wgResponse, wgCookie:\n", "\tcase wgResponse:\n"}},
		Catch:  []string{"relay-core"},
	},
	{
		ID:     "handshake-size-unchecked",
		Breaks: "the relay reads a datagram as a handshake message only at that message's size",
		Edits:  []Edit{{relayCore, "k == wgInitiation && len(b) == 148,", "k == wgInitiation && len(b) >= 148,"}},
		Catch:  []string{"relay-core"},
	},
	{
		ID:     "crossing-ignores-moved-endpoint",
		Breaks: "an initiation from an end whose endpoint changed after the peer's went on crosses nothing, since the peer's went to the old endpoint",
		Edits:  []Edit{{relayCore, "!d.answered.After(peer.initiated) && !d.opened.After(peer.initiated)", "!d.answered.After(peer.initiated)"}},
		Catch:  []string{"relay-core"},
	},
	{
		ID:     "same-endpoint-opens-window",
		Breaks: "only a registration that changes the endpoint opens the window for judging crossings, so a periodic claim lets no forged initiation hold the other end back",
		Edits:  []Edit{{relayCore, "\tif r.Endpoint != d.Endpoint {\n\t\td.opened = now", "\tif true {\n\t\td.opened = now"}},
		Catch:  []string{"relay-core"},
	},
	{
		ID:     "push-forgets-handshakes",
		Breaks: "a table push keeps each unchanged direction's handshake record, so a push between two initiations still lets the rule judge them",
		Edits:  []Edit{{relayCore, "\t\t\t\td.opened, d.initiated, d.answered = old.opened, old.initiated, old.answered\n", ""}},
		Catch:  []string{"relay-core"},
	},
	{
		ID:     "release-order-partial",
		Breaks: "the release order is total, so the older of an edge's two initiations goes however many batches one release holds",
		Edits:  []Edit{{relayCore, "\tcase az && bz:\n\t\treturn 0\n\tcase az:\n\t\treturn 1\n\tcase bz:\n\t\treturn -1\n", "\tcase az || bz:\n\t\treturn 0\n"}},
		Catch:  []string{"relay-core"},
	},
	{
		ID:     "host-scope-unchecked",
		Breaks: "a host attaches only into the networks its scope admits",
		Edits:  []Edit{{cpPlane, "n, err := ResolveNetworkIn(tx, h.Scope, req.Network)", "n, err := ResolveNetworkIn(tx, Global(), req.Network); _ = h"}},
		Catch:  []string{"cp", "sim", "e2e"},
	},
	{
		ID:     "emptied-scope-admits-all",
		Breaks: "a scope listing no network admits none, so one emptied by its networks' deletion never reads as global",
		Edits:  []Edit{{storeGo, "return s.Global || slices.Contains(s.Networks, n)", "return s.Global || len(s.Networks) == 0 || slices.Contains(s.Networks, n)"}},
		Catch:  []string{"cp", "sim"},
	},
	{
		ID:     "rescope-keeps-interfaces",
		Breaks: "rescoping a host revokes its interfaces in every network the change removes",
		Edits:  []Edit{{cpScope, "if compile.Connected(i) && compile.Built(i) && !sc.Admits(i.Network) {", "if false && compile.Connected(i) && compile.Built(i) && !sc.Admits(i.Network) {"}},
		Catch:  []string{"cp", "sim", "e2e"},
	},
	{
		ID:     "poll-outside-scope",
		Breaks: "a host's poll carries only the networks its scope admits, so a lost network's retained records show it nothing that network gains",
		Edits:  []Edit{{cpState, "if compile.Built(i) && h.Scope.Admits(i.Network) {", "if compile.Built(i) {"}},
		Catch:  []string{"cp", "sim"},
	},
	{
		ID:     "rescope-unbumped",
		Breaks: "a rescope moves its host's generation, so the host's agent drops a lost network even when nothing in it was revoked",
		Edits:  []Edit{{cpScope, "\tif err := bumpHosts(tx, []model.HostID{h.ID}); err != nil {\n\t\treturn store.Host{}, nil, err\n\t}\n\th, err = tx.Host(h.ID)", "\th, err = tx.Host(h.ID)"}},
		Catch:  []string{"cp"},
	},
	{
		ID:     "rescope-regained-unbumped",
		Breaks: "a rescope moves every network it gives back to a host that holds records there, so the host's next poll carries that network's state",
		Edits:  []Edit{{cpScope, "if compile.Built(i) && sc.Admits(i.Network) && !h.Scope.Admits(i.Network) {", "if false {"}},
		Catch:  []string{"cp", "sim"},
	},
	{
		ID:     "attach-answers-ended",
		Breaks: "an attach answer read after a rescope ended its interface carries nothing of the network the host lost",
		Edits:  []Edit{{cpState, "if i.State != api.Live {\n\t\treturn api.NetworkState{}, apiErr(api.CodeConflict,", "if false {\n\t\treturn api.NetworkState{}, apiErr(api.CodeConflict,"}},
		Catch:  []string{"cp"},
	},
	{
		ID:     "attach-answers-other-host",
		Breaks: "an attach answer reads only its own host's interface, so an identifier another host took since shows nothing of that host's network",
		Edits:  []Edit{{cpState, "if err == nil && i.Host != host {", "if false {"}},
		Catch:  []string{"cp"},
	},
	{
		ID:     "late-attach-answer-merged",
		Breaks: "an attach answer that arrives after a poll dropped its network leaves the network dropped",
		Edits:  []Edit{{apiState, "if ok && held.Revision > n.Revision || !ok && n.Revision <= h.Generation {", "if ok && held.Revision > n.Revision {"}},
		Catch:  []string{"api"},
	},
	{
		ID:     "rescope-keeps-gateways",
		Breaks: "rescoping a host revokes its gateways too, which ends the development machines behind them",
		Edits:  []Edit{{cpScope, "if compile.Connected(i) && compile.Built(i) && !sc.Admits(i.Network) {", "if compile.Connected(i) && i.Kind == api.Workload && !sc.Admits(i.Network) {"}},
		Catch:  []string{"cp"},
	},
	{
		ID:     "empty-scope-host-managed",
		Breaks: "a host that admits nothing answers to the global admin alone, since every scope holds an empty one",
		Edits:  []Edit{{cpScope, "return by.Global || !sc.Global && len(sc.Networks) > 0 && sc.Within(by)", "return by.Global || !sc.Global && sc.Within(by)"}},
		Catch:  []string{"cp"},
	},
	{
		ID:     "scoped-admin-creates-global-host",
		Breaks: "only the global admin registers a global host or widens one to every network",
		Edits:  []Edit{{cpScope, "\t\tif !by.Global {\n\t\t\treturn store.Scope{}, apiErr(api.CodeForbidden, \"only the global admin gives a host every network\")", "\t\tif false {\n\t\t\treturn store.Scope{}, apiErr(api.CodeForbidden, \"only the global admin gives a host every network\")"}},
		Catch:  []string{"cp", "e2e"},
	},
	{
		ID:     "scoped-admin-host-without-network",
		Breaks: "a scoped admin's hosts name at least one of its networks, so none leaves its management",
		Edits:  []Edit{{cpScope, "if len(req.Networks) == 0 && !by.Global {", "if false {"}},
		Catch:  []string{"cp"},
	},
	{
		ID:     "scoped-admin-deletes-foreign-host",
		Breaks: "a scoped admin deletes only hosts within its scope",
		Edits:  []Edit{{cpPlane, "h, err := ResolveHostIn(tx, by, ref)", "h, err := ResolveHost(tx, ref)"}},
		Catch:  []string{"cp", "cpserver"},
	},
	{
		ID:     "hosts-list-unfiltered",
		Breaks: "a scoped admin lists only the hosts it manages",
		Edits:  []Edit{{cpScope, "return slices.DeleteFunc(hosts, func(h store.Host) bool { return !Manages(by, h.Scope) }), err", "return hosts, err"}},
		Catch:  []string{"cp", "cpserver"},
	},
	{
		ID:     "out-of-scope-forbidden",
		Breaks: "a network outside a principal's scope answers not_found, as a missing one does, so a tenant learns nothing of another's names",
		Edits:  []Edit{{cpScope, "\t\treturn store.Network{}, notFound(store.ErrNotFound, \"network \"+ref)", "\t\treturn store.Network{}, apiErr(api.CodeForbidden, \"network %s is outside the scope\", ref)"}},
		Catch:  []string{"cp", "cpserver"},
	},
	{
		ID:     "admin-token-without-network",
		Breaks: "an admin token manages at least one network",
		Edits:  []Edit{{cpScope, "\tif len(refs) == 0 {\n\t\treturn store.Scope{}, apiErr(api.CodeInvalid, \"an admin token manages at least one network\")", "\tif false {\n\t\treturn store.Scope{}, apiErr(api.CodeInvalid, \"an admin token manages at least one network\")"}},
		Catch:  []string{"cp"},
	},
	{
		ID:     "rescope-keeps-draining",
		Breaks: "rescoping a host revokes its interfaces still draining on their peers, not only its live ones",
		Edits:  []Edit{{cpScope, "if compile.Connected(i) && compile.Built(i) && !sc.Admits(i.Network) {", "if i.State == api.Live && compile.Built(i) && !sc.Admits(i.Network) {"}},
		Catch:  []string{"cp", "sim"},
	},
	{
		ID:     "service-skips-scope",
		Breaks: "creating a service checks its network against the caller's scope in the transaction that acts",
		Edits:  []Edit{{cpPlane, "(store.Service, error) {\n\tn, err := ResolveNetworkIn(tx, by, netRef)", "(store.Service, error) {\n\tn, err := ResolveNetworkIn(tx, Global(), netRef); _ = by"}},
		Catch:  []string{"cpserver", "e2e"},
	},
	{
		ID:     "rule-skips-scope",
		Breaks: "creating a rule checks its network against the caller's scope",
		Edits:  []Edit{{cpPlane, "(store.Rule, error) {\n\tn, err := ResolveNetworkIn(tx, by, netRef)", "(store.Rule, error) {\n\tn, err := ResolveNetworkIn(tx, Global(), netRef)"}},
		Catch:  []string{"cpserver"},
	},
	{
		ID:     "device-skips-scope",
		Breaks: "creating a development machine checks its network against the caller's scope",
		Edits:  []Edit{{cpPlane, "(store.Interface, error) {\n\tn, err := ResolveNetworkIn(tx, by, netRef)", "(store.Interface, error) {\n\tn, err := ResolveNetworkIn(tx, Global(), netRef); _ = by"}},
		Catch:  []string{"cpserver"},
	},
	{
		ID:     "device-gateway-elsewhere",
		Breaks: "a gateway of another network reads as absent, so a device request tells nothing of another tenant's interfaces",
		Edits:  []Edit{{cpPlane, "if err == nil && gw.Network != n.ID {", "if false {"}},
		Catch:  []string{"cp"},
	},
	{
		ID:     "deny-deletion-unbounded",
		Breaks: "deleting a deny that would connect pairs past the edge bound fails, as any change past a bound does",
		Edits:  []Edit{{cpPlane, "\t\tif err := overQuota(\"edges\", n.Quota.Edges, h.edgesBefore, h.edgesAfter); err != nil {\n\t\t\treturn err\n", "\t\tif err := overQuota(\"edges\", n.Quota.Edges, h.edgesAfter, h.edgesAfter); err != nil {\n\t\t\treturn err\n"}},
		Catch:  []string{"cp"},
	},
	{
		ID:     "read-skips-scope",
		Breaks: "a read naming a network checks it against the admin token's scope",
		Edits:  []Edit{{cpServer, "return cp.ResolveNetworkIn(tx, by, ref)", "by.Global = true\n\treturn cp.ResolveNetworkIn(tx, by, ref)"}},
		Catch:  []string{"cpserver", "e2e"},
	},
	{
		ID:     "revoke-skips-scope",
		Breaks: "an admin token revokes only interfaces of its networks",
		Edits:  []Edit{{cpScope, "if err == nil && !by.Admits(i.Network) {", "if err == nil && !by.Admits(i.Network) && false {"}},
		Catch:  []string{"cpserver"},
	},
	{
		ID:     "networks-list-unfiltered",
		Breaks: "an admin token lists only its networks",
		Edits:  []Edit{{cpHandlers, "\t\t\tif by.Admits(n.ID) {\n\t\t\t\tout = append(out, networkInfo(n))", "\t\t\tif by.Admits(n.ID) || true {\n\t\t\t\tout = append(out, networkInfo(n))"}},
		Catch:  []string{"cpserver", "e2e"},
	},
	{
		ID:     "scoped-admin-grants-egress",
		Breaks: "only the operator grants internet egress, whose traffic leaves from the operator's addresses",
		Edits:  []Edit{{cpPlane, "if req.To == api.Internet && req.Action != api.Deny && !by.Global {", "if false {"}},
		Catch:  []string{"cp", "cpserver"},
	},
	{
		ID:     "operator-route-admits-admin",
		Breaks: "an operator route refuses admin tokens",
		Edits:  []Edit{{cpServer, "\tif err == nil && !p.operator {\n\t\terr = errOperatorOnly", "\tif false {\n\t\terr = errOperatorOnly"}},
		Catch:  []string{"cpserver", "e2e"},
	},
	{
		ID:     "deleted-admin-reads-global",
		Breaks: "an admin token whose record is gone is refused at once, whatever a replica cached",
		Edits:  []Edit{{cpServer, "\tif errors.Is(err, store.ErrNotFound) {\n\t\treturn store.Scope{}, errUnauthorized\n\t}\n\treturn a.Scope, err", "\tif errors.Is(err, store.ErrNotFound) {\n\t\treturn cp.Global(), nil\n\t}\n\treturn a.Scope, err"}},
		Catch:  []string{"cpserver"},
	},
	{
		ID:     "quota-interfaces-unchecked",
		Breaks: "an attach past a network's interface quota fails and changes nothing",
		Edits:  []Edit{{cpPlane, "\t\tif err := overQuota(\"live interfaces\", n.Quota.Interfaces, held.live-1, held.live); err != nil {\n\t\t\treturn store.Interface{}, \"\", err", "\t\tif err := overQuota(\"live interfaces\", n.Quota.Interfaces, held.live, held.live); err != nil {\n\t\t\treturn store.Interface{}, \"\", err"}},
		Catch:  []string{"cp", "e2e"},
	},
	{
		ID:     "quota-edges-unchecked",
		Breaks: "an attach past a network's edge quota fails, so one tenant's policy cannot spend the relay ports every network shares",
		Edits:  []Edit{{cpPlane, "overQuota(\"edges\", n.Quota.Edges, edgesFrom, held.edgesAfter)", "overQuota(\"edges\", n.Quota.Edges, held.edgesAfter, held.edgesAfter)"}},
		Catch:  []string{"cp"},
	},
	{
		ID:     "quota-rules-unchecked",
		Breaks: "a rule past a network's rule quota fails",
		Edits:  []Edit{{cpPlane, "overQuota(\"rules\", n.Quota.Rules, len(rules), len(rules)+1)", "overQuota(\"rules\", n.Quota.Rules, len(rules)+1, len(rules)+1)"}},
		Catch:  []string{"cp", "e2e"},
	},
	{
		ID:     "quota-services-unchecked",
		Breaks: "a service past a network's service quota fails",
		Edits:  []Edit{{cpPlane, "if n.Quota.Services > 0 {", "if false {"}},
		Catch:  []string{"cp"},
	},
	{
		ID:     "quota-blocks-standing",
		Breaks: "a bound lowered below what a network holds stops growth only, so a change that adds nothing passes",
		Edits:  []Edit{{cpScope, "if bound > 0 && after > bound && after > before {", "if bound > 0 && after > bound {"}},
		Catch:  []string{"cp"},
	},
	{
		ID:     "limits-unapplied",
		Breaks: "a scoped principal's calls spend its limits",
		Edits:  []Edit{{cpServer, "if err == nil && p.scoped && rt.spends != nothing {", "if false {"}},
		Catch:  []string{"cpserver"},
	},
	{
		ID:     "scoped-host-unlimited",
		Breaks: "a host whose scope is not global counts as scoped for its limits",
		Edits:  []Edit{{cpServer, "return principal{host: host.ID, scoped: !host.Scope.Global}, err", "return principal{host: host.ID}, err"}},
		Catch:  []string{"cpserver"},
	},
	{
		ID:     "renewal-limited",
		Breaks: "a renewal spends no write, so a limit never costs a lease",
		Edits:  []Edit{{cpServer, "{\"POST /v1/agent/renew\", host, s.renew, nothing},", "{\"POST /v1/agent/renew\", host, s.renew, aWrite},"}},
		Catch:  []string{"cpserver"},
	},
	{
		ID:     "renewal-takes-a-slot",
		Breaks: "a renewal takes none of the calls a scoped host may have running, so a full cap never costs a lease",
		Edits:  []Edit{{cpServer, "{\"POST /v1/agent/renew\", host, s.renew, nothing},", "{\"POST /v1/agent/renew\", host, s.renew, aCall},"}},
		Catch:  []string{"cpserver"},
	},
	{
		ID:     "prune-drops-running",
		Breaks: "pruning keeps a bucket while a call runs, so its release finds the count it took",
		Edits:  []Edit{{cpLimits, "if b.inFlight == 0 && full {", "if full {"}},
		Catch:  []string{"cpserver"},
	},
	{
		ID:     "bucket-clock-runs-back",
		Breaks: "a call clocked before the bucket's last refills nothing and leaves the bucket's time",
		Edits:  []Edit{{cpLimits, "if d := now.Sub(b.at); d > 0 {", "if d := now.Sub(b.at); true {"}},
		Catch:  []string{"cpserver"},
	},
	{
		ID:     "retry-after-ignored",
		Breaks: "the client waits out a limited answer within its call's timeout",
		Edits:  []Edit{{cpclientGo, "\t\t\treturn &limited{wait: wait, err: &ae}", "\t\t\t_ = wait\n\t\t\treturn &ae"}},
		Catch:  []string{"cpserver"},
	},
	{
		ID:     "limited-aborts-agent",
		Breaks: "a limited call the client cannot wait out answers unavailable, which an agent retries rather than aborting the attach",
		Edits:  []Edit{{cpclientGo, "&api.Error{Code: api.CodeUnavailable, Message: \"limited: \" + l.err.Message}", "l.err"}},
		Catch:  []string{"cpserver"},
	},
	{
		ID:     "pg-host-scope-dropped",
		Breaks: "Postgres keeps a host's scope as it was put",
		Edits:  []Edit{{pgTx, "Global: h.Scope.Global, Networks: networks,", "Global: true, Networks: networks,"}},
		Catch:  []string{"pgstore"},
	},
	{
		ID:     "mem-host-scope-aliased",
		Breaks: "the memory store copies a host's scope, so a caller changing what it read changes nothing stored",
		Edits:  []Edit{{memStore, "func cloneHost(h store.Host) store.Host          { h.Scope.Networks = slices.Clone(h.Scope.Networks); return h }", "func cloneHost(h store.Host) store.Host          { return h }"}},
		Catch:  []string{"store"},
	},
	{
		ID:     "migration-scopes-earlier-hosts",
		Breaks: "hosts registered before scopes stay global",
		Edits:  []Edit{{pgScopes, "ALTER TABLE hosts ADD COLUMN global boolean NOT NULL DEFAULT true;", "ALTER TABLE hosts ADD COLUMN global boolean NOT NULL DEFAULT false;"}},
		Catch:  []string{"pgstore"},
	},
	{
		ID:     "egress-deny-lifted",
		Breaks: "a scoped caller may narrow internet egress and never widen it, so it cannot delete a deny to the internet",
		Edits:  []Edit{{cpPlane, "if r.To == \"\" && r.Deny && !by.Global {", "if false {"}},
		Catch:  []string{"cp"},
	},
	{
		ID:     "scoped-egress-deny-refused",
		Breaks: "a scoped caller may write a deny to the internet, which narrows what the operator granted",
		Edits:  []Edit{{cpPlane, "if req.To == api.Internet && req.Action != api.Deny && !by.Global {", "if req.To == api.Internet && !by.Global {"}},
		Catch:  []string{"cp"},
	},
	{
		ID:     "deleted-network-kept-in-scopes",
		Breaks: "a deleted network leaves every host's and admin's scope, so no scope keeps an identifier nothing can name again",
		Edits:  []Edit{{cpPlane, "\tif err := dropFromScopes(tx, n.ID); err != nil {\n\t\treturn err\n\t}\n", ""}},
		Catch:  []string{"cp"},
	},
	{
		ID:     "creation-drops-defaults",
		Breaks: "a network's creation gives each bound it leaves out the control plane's default",
		Edits:  []Edit{{cpPlane, "quota := mergeQuota(req.Quota, p.Config.Quota)", "quota := req.Quota"}},
		Catch:  []string{"cp"},
	},
	{
		ID:     "replacement-counts-from-revoked",
		Breaks: "a replacement's edges count from before its holder's revocation, so one that leaves the count where it was passes a lowered bound",
		Edits:  []Edit{{cpPlane, "edgesFrom, replaced = gone.edgesBefore, holder.ID", "edgesFrom, replaced = -1+0*gone.edgesBefore, holder.ID"}},
		Catch:  []string{"cp"},
	},
}
