//go:build linux

// Package e2e runs the real daemons in a namespace lab. It needs root:
//
//	scripts/e2e            # builds as you, runs the tests under sudo
package e2e

import (
	"cmp"
	"context"
	crand "crypto/rand"
	"errors"
	"fmt"
	"maps"
	"net"
	"net/netip"
	"os"
	"os/exec"
	"path/filepath"
	"regexp"
	"slices"
	"strconv"
	"strings"
	"sync"
	"testing"
	"time"

	"golang.org/x/net/dns/dnsmessage"

	"github.com/danthegoodman1/wirenet/internal/api"
	"github.com/danthegoodman1/wirenet/internal/devconf"
	"github.com/danthegoodman1/wirenet/internal/lab"
	"github.com/danthegoodman1/wirenet/internal/model"
	"github.com/danthegoodman1/wirenet/internal/store/pgstore/pgtest"
)

// newLab starts a lab for one test, named for it so a crashed run's leftovers
// are purged by the next.
func newLab(t *testing.T, name string, cpArgs ...string) *lab.Lab {
	t.Helper()
	if os.Geteuid() != 0 {
		t.Skip("needs root: scripts/e2e")
	}
	bin := os.Getenv("WIRENET_LAB_BIN")
	if bin == "" {
		var err error
		if bin, err = lab.Build(t.TempDir()); err != nil {
			t.Fatal(err)
		}
	}
	dir := t.TempDir()
	store := "memory"
	if os.Getenv("WIRENET_TEST_POSTGRES") != "" {
		// A schema of its own, so a test never sees another's records.
		store = pgtest.NewSchema(t)
	}
	l, err := lab.New(lab.Options{Name: name, Dir: dir, Bin: bin, Store: store, CPArgs: cpArgs, Log: testWriter{t}})
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() {
		if t.Failed() {
			t.Log(l.Logs(40))
		}
		if keep := os.Getenv("WIRENET_LAB_KEEP"); keep != "" && (t.Failed() || os.Getenv("WIRENET_LAB_KEEP_ALWAYS") != "") {
			keepFiles(dir, filepath.Join(keep, name))
		}
		l.Close()
	})
	return l
}

// keepFiles copies a failed lab's regular files, its logs among them.
func keepFiles(from, to string) {
	filepath.WalkDir(from, func(path string, d os.DirEntry, err error) error {
		if err != nil || !d.Type().IsRegular() {
			return nil
		}
		rel, _ := filepath.Rel(from, path)
		b, err := os.ReadFile(path)
		if err == nil {
			os.MkdirAll(filepath.Dir(filepath.Join(to, rel)), 0o755)
			os.WriteFile(filepath.Join(to, rel), b, 0o644)
		}
		return nil
	})
}

type testWriter struct{ t *testing.T }

func (w testWriter) Write(b []byte) (int, error) {
	w.t.Log(strings.TrimRight(string(b), "\n"))
	return len(b), nil
}

func must[T any](v T, err error) T {
	if err != nil {
		panic(err)
	}
	return v
}

// fastClocks keeps lease and drain clocks short enough for a test.
var fastClocks = []string{"--lease-ttl", "6s", "--drain-grace", "2s", "--quarantine4", "4s", "--retention", "30s", "--poll-timeout", "5s"}

// mustNotReach asserts a connection fails, both refused and silent drops
// counting as failure.
func mustNotReach(t *testing.T, ns string, addr netip.AddrPort, why string) {
	t.Helper()
	start := time.Now()
	if got, err := lab.Dial(ns, addr, 1500*time.Millisecond); err == nil {
		t.Errorf("%s: reached %v, which answered %q", why, addr, got)
	}
	if d := time.Since(start); d > 2*time.Second {
		t.Logf("%s: the check took %v", why, d)
	}
}

func TestTwoHostsReachEachOtherThroughARelayAndNothingElse(t *testing.T) {
	l := newLab(t, "e2ea", fastClocks...)
	ctx := context.Background()
	relay := must(l.AddRelay(ctx, "r1"))
	h1 := must(l.AddHost(ctx, "h1"))
	h2 := must(l.AddHost(ctx, "h2"))
	must(l.Admin.CreateNetwork(ctx, api.CreateNetwork{Name: "prod", Prefix4: netip.MustParsePrefix("10.100.0.0/16"), Relays: []model.RelayID{relay.ID}}))
	must(l.Admin.CreateService(ctx, "prod", api.CreateService{Name: "web", IPv4: true}))
	db := must(l.Admin.CreateService(ctx, "prod", api.CreateService{Name: "db", IPv4: true}))
	must(l.Admin.CreateRule(ctx, "prod", api.CreateRule{From: "web", To: "db", Proto: model.TCP, Ports: model.PortRange{Lo: 5432, Hi: 5432}}))

	start := time.Now()
	dbIf := must(h2.Attach(ctx, "db-1", "prod", "db"))
	t.Logf("db attached in %v", time.Since(start))
	start = time.Now()
	webIf := must(h1.Attach(ctx, "web-1", "prod", "web"))
	t.Logf("web attached in %v", time.Since(start))
	t.Logf("db %s in %s at %v/%v; web %s in %s", dbIf.Interface, dbIf.Namespace, dbIf.Addr6, dbIf.Addr4, webIf.Interface, webIf.Namespace)
	for _, a := range []netip.Addr{dbIf.Addr6, dbIf.Addr4} {
		must(lab.Serve(dbIf.Namespace, netip.AddrPortFrom(a, 5432), "db"))
		must(lab.Serve(dbIf.Namespace, netip.AddrPortFrom(a, 2222), "secret"))
	}
	must(lab.Serve(webIf.Namespace, netip.AddrPortFrom(webIf.Addr6, 8080), "web"))

	// Through the service address in each family, and to the backend's own
	// address.
	for _, addr := range []netip.Addr{db.Addr6, db.Addr4, dbIf.Addr6, dbIf.Addr4} {
		took, got, err := timeToReach(webIf.Namespace, netip.AddrPortFrom(addr, 5432), 20*time.Second)
		if err != nil || got != "db" {
			t.Fatalf("web to %v: %q %v", addr, got, err)
		}
		t.Logf("web reached %v after %v", addr, took)
	}

	// Policy names port 5432 alone, and web to db alone.
	mustNotReach(t, webIf.Namespace, netip.AddrPortFrom(dbIf.Addr6, 2222), "a port the rule does not name, IPv6")
	mustNotReach(t, webIf.Namespace, netip.AddrPortFrom(dbIf.Addr4, 2222), "a port the rule does not name, IPv4")
	mustNotReach(t, dbIf.Namespace, netip.AddrPortFrom(webIf.Addr6, 8080), "the reverse direction")
	// The underlay, the relay and the control plane are out of reach.
	mustNotReach(t, webIf.Namespace, netip.MustParseAddrPort("10.213.255.1:18443"), "the control plane, IPv4")
	mustNotReach(t, webIf.Namespace, netip.AddrPortFrom(relay.Addr, 9092), "the relay, IPv4")
	mustNotReach(t, webIf.Namespace, netip.AddrPortFrom(relay.Addr6, 9092), "the relay, IPv6")
	mustNotReach(t, webIf.Namespace, netip.AddrPortFrom(h1.Addr, 9091), "its own host's agent, IPv4")

	// The data path ran through the relay, which forwarded and admitted
	// registrations.
	m := must(lab.Metrics(relay.Telemetry))
	if v := metric(m, `wirenet_relay_forwarded_packets_total`); v == 0 {
		t.Errorf("the relay forwarded nothing:\n%s", grep(m, "wirenet_relay"))
	}
	if v := metric(m, `wirenet_relay_registrations_total{result="accepted"}`); v < 2 {
		t.Errorf("the relay accepted %v registrations, want both directions", v)
	}
	am := must(lab.Metrics(h1.Telemetry))
	if v := metric(am, `wirenet_agent_local_calls_total{call="attach",result="ok"}`); v != 1 {
		t.Errorf("agent attach count %v", v)
	}

	// Revocation reaches the peer: db's host removes web, so web reaches
	// nothing, though its own host may still hold it.
	if err := l.Admin.Revoke(ctx, webIf.Interface); err != nil {
		t.Fatal(err)
	}
	revoked := time.Now()
	defer func() { t.Logf("revocation took effect within %v", time.Since(revoked)) }()
	deadline := time.Now().Add(10 * time.Second)
	for {
		_, err := lab.Dial(webIf.Namespace, netip.AddrPortFrom(dbIf.Addr6, 5432), time.Second)
		if err != nil {
			break
		}
		if time.Now().After(deadline) {
			t.Fatal("a revoked interface still reaches db")
		}
		time.Sleep(200 * time.Millisecond)
	}
	mustNotReach(t, webIf.Namespace, netip.AddrPortFrom(db.Addr4, 5432), "a revoked interface, IPv4 service")
}

// TestAWildcardOpensAServiceAndADenyClosesItAgain opens db to every other
// service, takes the sandboxes back out with a deny, lets the sandboxes reach
// every other service, and lets web reach the sandboxes on everything but
// TCP 22. Each claim is asserted in both families, including that two
// sandboxes cannot reach each other and that ICMP passes where the deny
// took TCP 22 out of an allow for any protocol; then removing the deny
// opens db to the sandboxes without a restart.
func TestAWildcardOpensAServiceAndADenyClosesItAgain(t *testing.T) {
	l := newLab(t, "e2eo", fastClocks...)
	ctx := context.Background()
	relay := must(l.AddRelay(ctx, "r1"))
	h1 := must(l.AddHost(ctx, "h1"))
	h2 := must(l.AddHost(ctx, "h2"))
	h3 := must(l.AddHost(ctx, "h3"))
	must(l.Admin.CreateNetwork(ctx, api.CreateNetwork{Name: "prod", Prefix4: netip.MustParsePrefix("10.101.0.0/16"), Relays: []model.RelayID{relay.ID}}))
	db := must(l.Admin.CreateService(ctx, "prod", api.CreateService{Name: "db", IPv4: true}))
	web := must(l.Admin.CreateService(ctx, "prod", api.CreateService{Name: "web", IPv4: true}))
	box := must(l.Admin.CreateService(ctx, "prod", api.CreateService{Name: "box", IPv4: true}))
	rule := func(from, to string, proto model.Proto, ports model.PortRange, action api.Action) api.Rule {
		return must(l.Admin.CreateRule(ctx, "prod", api.CreateRule{From: from, To: to, Proto: proto, Ports: ports, Action: action}))
	}
	rule(api.Wildcard, "db", model.TCP, model.PortRange{Lo: 5432, Hi: 5432}, api.Allow)
	boxOut := rule("box", "db", model.AnyProto, model.PortRange{}, api.Deny)
	rule("box", api.Wildcard, model.TCP, model.PortRange{Lo: 8080, Hi: 8080}, api.Allow)
	rule("web", "box", model.AnyProto, model.PortRange{}, api.Allow)
	rule("web", "box", model.TCP, model.PortRange{Lo: 22, Hi: 22}, api.Deny)

	dbIf := must(h2.Attach(ctx, "db-1", "prod", "db"))
	webIf := must(h1.Attach(ctx, "web-1", "prod", "web"))
	box1 := must(h1.Attach(ctx, "box-1", "prod", "box"))
	box2 := must(h3.Attach(ctx, "box-2", "prod", "box"))
	for _, a := range []netip.Addr{dbIf.Addr6, dbIf.Addr4} {
		must(lab.Serve(dbIf.Namespace, netip.AddrPortFrom(a, 5432), "db"))
	}
	for _, a := range []netip.Addr{webIf.Addr6, webIf.Addr4} {
		must(lab.Serve(webIf.Namespace, netip.AddrPortFrom(a, 8080), "web"))
	}
	for _, b := range []api.LocalInterface{box1, box2} {
		for _, a := range []netip.Addr{b.Addr6, b.Addr4} {
			for _, port := range []uint16{22, 8080, 8081} {
				must(lab.Serve(b.Namespace, netip.AddrPortFrom(a, port), b.Name))
			}
		}
	}
	reach := func(ns string, to netip.AddrPort, want string) {
		t.Helper()
		if _, got, err := timeToReach(ns, to, 20*time.Second); err != nil || got != want {
			t.Fatalf("to %v: %q %v, want %q", to, got, err, want)
		}
	}
	for _, a := range []netip.Addr{db.Addr6, db.Addr4} {
		reach(webIf.Namespace, netip.AddrPortFrom(a, 5432), "db")
	}
	for _, a := range []netip.Addr{web.Addr6, web.Addr4} {
		reach(box1.Namespace, netip.AddrPortFrom(a, 8080), "web")
		reach(box2.Namespace, netip.AddrPortFrom(a, 8080), "web")
	}
	for _, a := range []netip.Addr{box2.Addr6, box2.Addr4} {
		reach(webIf.Namespace, netip.AddrPortFrom(a, 8081), "box-2")
		if out, err := exec.Command("ip", "netns", "exec", webIf.Namespace, "ping", "-c", "1", "-W", "5", a.String()).CombinedOutput(); err != nil {
			t.Fatalf("web pinging box-2 at %v, which the deny on TCP 22 leaves open: %v\n%s", a, err, out)
		}
	}

	for _, a := range []netip.Addr{db.Addr6, db.Addr4, dbIf.Addr6, dbIf.Addr4} {
		mustNotReach(t, box1.Namespace, netip.AddrPortFrom(a, 5432), "a sandbox the deny takes out of db's wildcard")
	}
	for _, a := range []netip.Addr{box2.Addr6, box2.Addr4} {
		mustNotReach(t, box1.Namespace, netip.AddrPortFrom(a, 8080), "a sandbox reaching another through its own wildcard")
		mustNotReach(t, webIf.Namespace, netip.AddrPortFrom(a, 22), "a port denied out of an allow for any protocol")
	}
	for _, a := range []netip.Addr{box.Addr6, box.Addr4} {
		mustNotReach(t, box1.Namespace, netip.AddrPortFrom(a, 8080), "a sandbox reaching its own service")
	}

	var grants []string
	for _, g := range must(l.Admin.Policy(ctx, "prod")) {
		grants = append(grants, fmt.Sprintf("%s>%s %s/%s", g.FromName, g.ToName, g.Proto, g.Ports))
	}
	for _, want := range []string{"web>db tcp/5432", "box>web tcp/8080", "web>box tcp/1-21", "web>box tcp/23-65535", "web>box udp/*", "web>box other/*"} {
		if !slices.Contains(grants, want) {
			t.Errorf("policy lacks %s: %v", want, grants)
		}
	}
	for _, g := range grants {
		if strings.HasPrefix(g, "box>db") || strings.HasPrefix(g, "box>box") {
			t.Errorf("policy grants %s: %v", g, grants)
		}
	}

	if err := l.Admin.DeleteRule(ctx, "prod", boxOut.ID); err != nil {
		t.Fatal(err)
	}
	for _, a := range []netip.Addr{db.Addr6, db.Addr4} {
		reach(box1.Namespace, netip.AddrPortFrom(a, 5432), "db")
		reach(box2.Namespace, netip.AddrPortFrom(a, 5432), "db")
	}

	// The deny again takes both sandboxes' edges to db dormant, and each
	// agent withdraws its two directions' endpoints at the relay as it
	// removes the peer. Lifted again, every sandbox reaches db within
	// WireGuard's 5-second handshake retry.
	withdrawn := func() float64 {
		return metric(must(lab.Metrics(relay.Telemetry)), `wirenet_relay_registrations_total{result="withdrawn"}`)
	}
	before := withdrawn()
	boxOut = rule("box", "db", model.AnyProto, model.PortRange{}, api.Deny)
	for start := time.Now(); withdrawn() < before+4; time.Sleep(50 * time.Millisecond) {
		if time.Since(start) > 10*time.Second {
			t.Fatalf("the relay committed %v withdrawals after the deny returned, want 4", withdrawn()-before)
		}
	}
	for _, a := range []netip.Addr{db.Addr6, db.Addr4} {
		mustNotReach(t, box1.Namespace, netip.AddrPortFrom(a, 5432), "a sandbox the returned deny takes out of db's wildcard")
	}
	if err := l.Admin.DeleteRule(ctx, "prod", boxOut.ID); err != nil {
		t.Fatal(err)
	}
	for _, b := range []api.LocalInterface{box1, box2} {
		for _, a := range []netip.Addr{db.Addr6, db.Addr4} {
			took, got, err := timeToReach(b.Namespace, netip.AddrPortFrom(a, 5432), 20*time.Second)
			if err != nil || got != "db" || took > 4*time.Second {
				t.Fatalf("%s to db at %v after the deny lifted again: %q in %v, %v; want db within a handshake retry", b.Name, a, got, took, err)
			}
			t.Logf("%s reached db at %v in %v", b.Name, a, took)
		}
	}
}

// metric returns a sample's value from metrics text, summing every series
// whose name and labels start with sel.
func metric(text, sel string) float64 {
	var sum float64
	for _, line := range strings.Split(text, "\n") {
		if strings.HasPrefix(line, "#") || !strings.HasPrefix(line, strings.TrimSuffix(sel, "}")) {
			continue
		}
		f := strings.Fields(line)
		if len(f) < 2 {
			continue
		}
		v, err := strconv.ParseFloat(f[len(f)-1], 64)
		if err == nil {
			sum += v
		}
	}
	return sum
}

func grep(text, pattern string) string {
	re := regexp.MustCompile(pattern)
	var out []string
	for _, line := range strings.Split(text, "\n") {
		if re.MatchString(line) && !strings.HasPrefix(line, "#") {
			out = append(out, line)
		}
	}
	return strings.Join(out, "\n")
}

// webDB creates network prod over relays, with web allowed to reach db on
// 5432, IPv6 only.
func webDB(t *testing.T, l *lab.Lab, relays ...*lab.Relay) api.ServiceInfo {
	t.Helper()
	ctx := context.Background()
	var ids []model.RelayID
	for _, r := range relays {
		ids = append(ids, r.ID)
	}
	must(l.Admin.CreateNetwork(ctx, api.CreateNetwork{Name: "prod", Relays: ids}))
	must(l.Admin.CreateService(ctx, "prod", api.CreateService{Name: "web"}))
	db := must(l.Admin.CreateService(ctx, "prod", api.CreateService{Name: "db"}))
	must(l.Admin.CreateRule(ctx, "prod", api.CreateRule{From: "web", To: "db", Proto: model.TCP, Ports: model.PortRange{Lo: 5432, Hi: 5432}}))
	return db
}

// attachDB attaches a db backend that answers with its name.
func attachDB(t *testing.T, h *lab.Host, name string) api.LocalInterface {
	t.Helper()
	i := must(h.Attach(context.Background(), name, "prod", "db"))
	must(lab.Serve(i.Namespace, netip.AddrPortFrom(i.Addr6, 5432), name))
	return i
}

// timeToReach measures how long until a fresh connection from ns reaches
// addr, trying every 50ms.
func timeToReach(ns string, addr netip.AddrPort, limit time.Duration) (time.Duration, string, error) {
	start := time.Now()
	for time.Since(start) < limit {
		got, err := lab.Dial(ns, addr, 300*time.Millisecond)
		if err == nil {
			return time.Since(start), got, nil
		}
		time.Sleep(50 * time.Millisecond)
	}
	return 0, "", fmt.Errorf("unreachable for %v", limit)
}

func TestAnAgentKilledMidLifeAdoptsItsInterfacesAndLeaksNothing(t *testing.T) {
	l := newLab(t, "e2eb", fastClocks...)
	ctx := context.Background()
	relay := must(l.AddRelay(ctx, "r1"))
	h1 := must(l.AddHost(ctx, "h1"))
	h2 := must(l.AddHost(ctx, "h2"))
	svc := webDB(t, l, relay)
	attachDB(t, h2, "db-1")
	web := must(h1.Attach(ctx, "web-1", "prod", "web"))
	dbAddr := netip.AddrPortFrom(svc.Addr6, 5432)
	if _, err := lab.DialUntil(web.Namespace, dbAddr, 20*time.Second); err != nil {
		t.Fatal(err)
	}
	portsBefore := must(h1.DevicePorts())

	// The data path outlives the agent.
	h1.Agent.Kill()
	if got, err := lab.Dial(web.Namespace, dbAddr, 2*time.Second); err != nil || got != "db-1" {
		t.Fatalf("with the agent dead: %q %v", got, err)
	}
	if err := h1.Restart(); err != nil {
		t.Fatal(err)
	}
	// Attaching the same workload name returns the interface it has.
	again := must(h1.Attach(ctx, "web-1", "prod", "web"))
	if again.Interface != web.Interface || again.Namespace != web.Namespace {
		t.Fatalf("a retried attach built %s, want %s", again.Interface, web.Interface)
	}
	web2 := must(h1.Attach(ctx, "web-2", "prod", "web"))
	for _, ns := range []string{web.Namespace, web2.Namespace} {
		if _, err := lab.DialUntil(ns, dbAddr, 20*time.Second); err != nil {
			t.Fatalf("%s after restart: %v", ns, err)
		}
	}
	// Detaching removes the namespace and frees the device's port.
	must(h1.Detach(ctx, web2.Interface))
	if ns := h1.Namespaces(); len(ns) != 1 || ns[0] != web.Namespace {
		t.Fatalf("namespaces after detach: %v", ns)
	}
	if ports := must(h1.DevicePorts()); !equalPorts(ports, portsBefore) {
		t.Fatalf("device ports %v after detach, %v before the second attach", ports, portsBefore)
	}
	// A detach the caller lost the answer to answers that the interface
	// is gone.
	var ae *api.Error
	if _, err := h1.Detach(ctx, web2.Interface); !errors.As(err, &ae) || ae.Code != api.CodeNotFound {
		t.Fatalf("a retried detach: %v", err)
	}
}

func equalPorts(a, b []uint16) bool {
	set := func(s []uint16) map[uint16]bool {
		m := map[uint16]bool{}
		for _, p := range s {
			m[p] = true
		}
		return m
	}
	x, y := set(a), set(b)
	if len(x) != len(y) {
		return false
	}
	for p := range x {
		if !y[p] {
			return false
		}
	}
	return true
}

func TestTrafficFailsOverWhenItsRelayDies(t *testing.T) {
	l := newLab(t, "e2ec", fastClocks...)
	ctx := context.Background()
	r1 := must(l.AddRelay(ctx, "r1"))
	r2 := must(l.AddRelay(ctx, "r2"))
	h1 := must(l.AddHost(ctx, "h1"))
	h2 := must(l.AddHost(ctx, "h2"))
	svc := webDB(t, l, r1, r2)
	attachDB(t, h2, "db-1")
	web := must(h1.Attach(ctx, "web-1", "prod", "web"))
	dbAddr := netip.AddrPortFrom(svc.Addr6, 5432)
	if _, err := lab.DialUntil(web.Namespace, dbAddr, 20*time.Second); err != nil {
		t.Fatal(err)
	}
	// The one edge sends through one relay of the two.
	carrier, other := r1, r2
	if metric(must(lab.Metrics(r1.Telemetry)), "wirenet_relay_forwarded_packets_total") == 0 {
		carrier, other = r2, r1
	}
	if metric(must(lab.Metrics(carrier.Telemetry)), "wirenet_relay_forwarded_packets_total") == 0 {
		t.Fatal("neither relay forwarded the edge's traffic")
	}
	carrier.Kill()
	took, _, err := timeToReach(web.Namespace, dbAddr, 15*time.Second)
	if err != nil {
		t.Fatalf("no failover: %v", err)
	}
	t.Logf("failover: a new connection reached db %v after %s died", took, carrier.Name)
	if metric(must(lab.Metrics(other.Telemetry)), "wirenet_relay_forwarded_packets_total") == 0 {
		t.Fatalf("%s, the survivor, forwarded nothing", other.Name)
	}
	if took > 3*time.Second {
		t.Errorf("failover took %v", took)
	}
}

func TestANetworksEdgesSpreadOverItsRelays(t *testing.T) {
	l := newLab(t, "e2en", fastClocks...)
	ctx := context.Background()
	r1 := must(l.AddRelay(ctx, "r1"))
	r2 := must(l.AddRelay(ctx, "r2"))
	h1 := must(l.AddHost(ctx, "h1"))
	h2 := must(l.AddHost(ctx, "h2"))
	svc := webDB(t, l, r1, r2)
	for i := range 4 {
		attachDB(t, h2, fmt.Sprintf("db-%d", i+1))
	}
	dbAddr := netip.AddrPortFrom(svc.Addr6, 5432)
	var webs []api.LocalInterface
	for i := range 4 {
		web := must(h1.Attach(ctx, fmt.Sprintf("web-%d", i+1), "prod", "web"))
		if _, err := lab.DialUntil(web.Namespace, dbAddr, 20*time.Second); err != nil {
			t.Fatal(err)
		}
		webs = append(webs, web)
	}
	// Sixteen edges over two relays, all on one with odds of 2 in 65,536;
	// each web dials until it has reached every backend, so every edge
	// carries traffic.
	for _, web := range webs {
		reached := map[string]bool{}
		for try := 0; len(reached) < 4 && try < 200; try++ {
			if got, err := lab.Dial(web.Namespace, dbAddr, time.Second); err == nil {
				reached[got] = true
			}
		}
		if len(reached) < 4 {
			t.Fatalf("%s reached only %v", web.Name, reached)
		}
	}
	for _, r := range []*lab.Relay{r1, r2} {
		if metric(must(lab.Metrics(r.Telemetry)), "wirenet_relay_forwarded_packets_total") == 0 {
			t.Fatalf("%s forwarded nothing; the network's edges all took the other relay", r.Name)
		}
	}
	// Each end counts its peers on each relay, and both hosts see the same
	// sixteen edges split the same way.
	split := func(h *lab.Host) [2]float64 {
		m := must(lab.Metrics(h.Telemetry))
		return [2]float64{
			metric(m, fmt.Sprintf(`wirenet_agent_relay_peers{relay="%s"}`, r1.ID)),
			metric(m, fmt.Sprintf(`wirenet_agent_relay_peers{relay="%s"}`, r2.ID)),
		}
	}
	deadline := time.Now().Add(5 * time.Second)
	for {
		a, b := split(h1), split(h2)
		if a == b && a[0]+a[1] == 16 && a[0] > 0 && a[1] > 0 {
			t.Logf("edges per relay: %s %v, %s %v", r1.Name, a[0], r2.Name, a[1])
			break
		}
		if time.Now().After(deadline) {
			t.Fatalf("peers per relay: h1 %v, h2 %v; want the same split of 16 edges over both", a, b)
		}
		time.Sleep(200 * time.Millisecond)
	}
}

func TestARelayRestartsFromItsDisk(t *testing.T) {
	// A long registration period and resends that end 650ms after an
	// install: only the relay's disk can restore the directions within the
	// test.
	l := newLab(t, "e2ed", fastClocks...)
	ctx := context.Background()
	relay := must(l.AddRelay(ctx, "r1"))
	h1 := must(l.AddHost(ctx, "h1", "--register-every", "5m", "--register-retries", "3"))
	h2 := must(l.AddHost(ctx, "h2", "--register-every", "5m", "--register-retries", "3"))
	svc := webDB(t, l, relay)
	attachDB(t, h2, "db-1")
	web := must(h1.Attach(ctx, "web-1", "prod", "web"))
	dbAddr := netip.AddrPortFrom(svc.Addr6, 5432)
	if _, err := lab.DialUntil(web.Namespace, dbAddr, 20*time.Second); err != nil {
		t.Fatal(err)
	}
	time.Sleep(time.Second)
	relay.Kill()
	if err := relay.Start(); err != nil {
		t.Fatal(err)
	}
	took, _, err := timeToReach(web.Namespace, dbAddr, 10*time.Second)
	if err != nil {
		t.Fatalf("after the relay restarted: %v", err)
	}
	t.Logf("a restarted relay carried traffic again after %v", took)
	m := must(lab.Metrics(relay.Telemetry))
	if v := metric(m, `wirenet_relay_registrations_total{result="accepted"}`); v != 0 {
		t.Errorf("the restarted relay needed %v registrations", v)
	}
}

func TestCoLocatedInterfacesPeerOverTheHostLoopback(t *testing.T) {
	l := newLab(t, "e2ee", fastClocks...)
	ctx := context.Background()
	relay := must(l.AddRelay(ctx, "r1"))
	h1 := must(l.AddHost(ctx, "h1"))
	svc := webDB(t, l, relay)
	attachDB(t, h1, "db-1")
	web := must(h1.Attach(ctx, "web-1", "prod", "web"))
	if _, err := lab.DialUntil(web.Namespace, netip.AddrPortFrom(svc.Addr6, 5432), 20*time.Second); err != nil {
		t.Fatal(err)
	}
	if v := metric(must(lab.Metrics(relay.Telemetry)), "wirenet_relay_forwarded_packets_total"); v != 0 {
		t.Errorf("the relay forwarded %v packets between interfaces on one host", v)
	}
}

func TestAReplacedBackendKeepsItsConnectionsUntilTheGracePeriodEnds(t *testing.T) {
	l := newLab(t, "e2ef", fastClocks...)
	ctx := context.Background()
	relay := must(l.AddRelay(ctx, "r1"))
	h1 := must(l.AddHost(ctx, "h1"))
	h2 := must(l.AddHost(ctx, "h2"))
	svc := webDB(t, l, relay)
	old := attachDB(t, h2, "db-old")
	web := must(h1.Attach(ctx, "web-1", "prod", "web"))
	dbAddr := netip.AddrPortFrom(svc.Addr6, 5432)
	if _, err := lab.DialUntil(web.Namespace, dbAddr, 20*time.Second); err != nil {
		t.Fatal(err)
	}
	var held net.Conn
	if err := lab.InNS(web.Namespace, func() error {
		var err error
		held, err = net.DialTimeout("tcp", dbAddr.String(), 2*time.Second)
		return err
	}); err != nil {
		t.Fatal(err)
	}
	defer held.Close()
	attachDB(t, h2, "db-new")
	must(h2.Detach(ctx, old.Interface))
	// New connections reach the new backend.
	deadline := time.Now().Add(10 * time.Second)
	for {
		got, err := lab.Dial(web.Namespace, dbAddr, time.Second)
		if err == nil && got == "db-new" {
			break
		}
		if time.Now().After(deadline) {
			t.Fatalf("new connections still reach %q (%v)", got, err)
		}
		time.Sleep(100 * time.Millisecond)
	}
	if _, err := held.Write([]byte("still there")); err != nil {
		t.Fatalf("the held connection broke before the grace period ended: %v", err)
	}
}

func TestARelayPeerWithoutKeepaliveHoldsItsNATMappingByRegistering(t *testing.T) {
	l := newLab(t, "e2eg", fastClocks...)
	ctx := context.Background()
	relay := must(l.AddRelay(ctx, "r1"))
	h1 := must(l.AddHost(ctx, "h1"))
	// db sits behind a NAT that forgets an idle mapping after 3 seconds and
	// gives every new mapping a fresh port; its agent registers every
	// second.
	h2 := must(l.AddHostBehindNAT(ctx, "h2", lab.NAT{UDPTimeout: 3 * time.Second, Random: true}, "--register-every", "1s"))
	svc := webDB(t, l, relay)
	attachDB(t, h2, "db-1")
	web := must(h1.Attach(ctx, "web-1", "prod", "web"))
	dbAddr := netip.AddrPortFrom(svc.Addr6, 5432)
	if _, err := lab.DialUntil(web.Namespace, dbAddr, 20*time.Second); err != nil {
		t.Fatal(err)
	}
	// Idle well past the NAT's timeout: no keepalive runs on relay peers,
	// so only registrations keep db reachable.
	time.Sleep(8 * time.Second)
	if took, _, err := timeToReach(web.Namespace, dbAddr, 5*time.Second); err != nil {
		t.Fatalf("db unreachable after idling behind its NAT: %v", err)
	} else {
		t.Logf("after idling: reached db in %v", took)
	}
	// The NAT forgets everything; db's next registration arrives from a new
	// port, and the relay follows it.
	if err := h2.FlushNAT(); err != nil {
		t.Fatal(err)
	}
	took, _, err := timeToReach(web.Namespace, dbAddr, 10*time.Second)
	if err != nil {
		t.Fatalf("after the NAT rebound: %v", err)
	}
	t.Logf("after the NAT rebound: reached db in %v", took)
}

func TestWorkloadsResolveTheServicesTheyMayReach(t *testing.T) {
	l := newLab(t, "e2eh", fastClocks...)
	ctx := context.Background()
	relay := must(l.AddRelay(ctx, "r1"))
	h1 := must(l.AddHost(ctx, "h1"))
	h2 := must(l.AddHost(ctx, "h2"))
	must(l.Admin.CreateNetwork(ctx, api.CreateNetwork{Name: "shop", Prefix4: netip.MustParsePrefix("10.101.0.0/16"), Relays: []model.RelayID{relay.ID}}))
	must(l.Admin.CreateService(ctx, "shop", api.CreateService{Name: "web", IPv4: true}))
	must(l.Admin.CreateService(ctx, "shop", api.CreateService{Name: "edge"}))
	db := must(l.Admin.CreateService(ctx, "shop", api.CreateService{Name: "db", IPv4: true}))
	must(l.Admin.CreateService(ctx, "shop", api.CreateService{Name: "admin"}))
	for _, from := range []string{"web", "edge"} {
		must(l.Admin.CreateRule(ctx, "shop", api.CreateRule{From: from, To: "db", Proto: model.TCP, Ports: model.PortRange{Lo: 5432, Hi: 5432}}))
	}
	dbIf := must(h2.Attach(ctx, "db-1", "shop", "db"))
	must(lab.Serve(dbIf.Namespace, netip.AddrPortFrom(dbIf.Addr6, 5432), "db"))
	web := must(h1.Attach(ctx, "web-1", "shop", "web"))
	edge := must(h1.Attach(ctx, "edge-1", "shop", "edge"))
	if web.Resolver.String() != "127.0.0.53" || web.Search != "shop.internal" {
		t.Fatalf("the agent told the runtime resolver %v, search %q", web.Resolver, web.Search)
	}
	name := "db.shop.internal."
	var got []netip.Addr
	deadline := time.Now().Add(10 * time.Second)
	for {
		var err error
		got, _, err = lab.Lookup(web.Namespace, name, dnsmessage.TypeAAAA)
		if err == nil && len(got) == 1 {
			break
		}
		if time.Now().After(deadline) {
			t.Fatalf("AAAA %s from web: %v %v", name, got, err)
		}
		time.Sleep(100 * time.Millisecond)
	}
	if got[0] != db.Addr6 {
		t.Fatalf("AAAA %s = %v, want %v", name, got, db.Addr6)
	}
	if a, _, err := lab.Lookup(web.Namespace, name, dnsmessage.TypeA); err != nil || len(a) != 1 || a[0] != db.Addr4 {
		t.Fatalf("A %s from an IPv4 client: %v %v", name, a, err)
	}
	// edge's service has no IPv4, so it gets no A record.
	if a, rc, err := lab.Lookup(edge.Namespace, name, dnsmessage.TypeA); err != nil || len(a) != 0 || rc != dnsmessage.RCodeSuccess {
		t.Fatalf("A %s from an IPv6-only client: %v %v %v", name, a, rc, err)
	}
	// No rule names admin, so it does not exist for web.
	if _, rc, err := lab.Lookup(web.Namespace, "admin.shop.internal.", dnsmessage.TypeAAAA); err != nil || rc != dnsmessage.RCodeNameError {
		t.Fatalf("admin from web: %v %v", rc, err)
	}
	// The resolved address carries traffic.
	if got, err := lab.DialUntil(web.Namespace, netip.AddrPortFrom(got[0], 5432), 10*time.Second); err != nil || got != "db" {
		t.Fatalf("dialing the resolved address: %q %v", got, err)
	}
	// A restarted agent serves names again.
	if err := h1.Restart(); err != nil {
		t.Fatal(err)
	}
	deadline = time.Now().Add(10 * time.Second)
	for {
		a, _, err := lab.Lookup(web.Namespace, name, dnsmessage.TypeAAAA)
		if err == nil && len(a) == 1 {
			break
		}
		if time.Now().After(deadline) {
			t.Fatalf("after the agent restarted: %v %v", a, err)
		}
		time.Sleep(100 * time.Millisecond)
	}
}

// TestAQuerySentWhileTheAgentRestartsWaitsAndIsAnswered runs the agent
// under systemd with a descriptor store: the resolver's sockets outlive the
// agent, so a query sent while it is down waits in the socket's buffer.
func TestAQuerySentWhileTheAgentRestartsWaitsAndIsAnswered(t *testing.T) {
	l := newLab(t, "e2ei", fastClocks...)
	ctx := context.Background()
	relay := must(l.AddRelay(ctx, "r1"))
	h1 := must(l.AddSystemdHost(ctx, "h1"))
	svc := webDB(t, l, relay)
	attachDB(t, h1, "db-1")
	web := must(h1.Attach(ctx, "web-1", "prod", "web"))
	name := "db.prod.internal."
	lookup := func() ([]netip.Addr, error) {
		a, _, err := lab.Lookup(web.Namespace, name, dnsmessage.TypeAAAA)
		return a, err
	}
	deadline := time.Now().Add(10 * time.Second)
	for {
		if a, err := lookup(); err == nil && len(a) == 1 && a[0] == svc.Addr6 {
			break
		}
		if time.Now().After(deadline) {
			t.Fatal("the resolver never answered")
		}
		time.Sleep(100 * time.Millisecond)
	}
	// A socket the resolver opened and stored closes when its interface
	// detaches, and the attach after it is answered.
	extra := must(h1.Attach(ctx, "web-2", "prod", "web"))
	must(h1.Detach(ctx, extra.Interface))
	attached := make(chan error, 1)
	go func() {
		_, err := h1.Attach(ctx, "web-3", "prod", "web")
		attached <- err
	}()
	select {
	case err := <-attached:
		if err != nil {
			t.Fatal(err)
		}
	case <-time.After(10 * time.Second):
		t.Fatal("an attach after a detach was never answered")
	}
	if err := sh("systemctl", "kill", "--signal=KILL", "--kill-whom=main", h1.Unit); err != nil {
		t.Fatal(err)
	}
	start := time.Now()
	a, _, err := lab.LookupWithin(web.Namespace, name, dnsmessage.TypeAAAA, 10*time.Second)
	if err != nil || len(a) != 1 || a[0] != svc.Addr6 {
		t.Fatalf("a query sent during the restart: %v %v", a, err)
	}
	t.Logf("a query sent as the agent died was answered after %v", time.Since(start))
}

func sh(args ...string) error {
	out, err := exec.Command(args[0], args[1:]...).CombinedOutput()
	if err != nil {
		return fmt.Errorf("%v: %v: %s", args, err, out)
	}
	return nil
}

func TestAnEgressGrantReachesTheInternetOnItsPortsAlone(t *testing.T) {
	l := newLab(t, "e2ej", fastClocks...)
	ctx := context.Background()
	relay := must(l.AddRelay(ctx, "r1"))
	h1 := must(l.AddHost(ctx, "h1"))
	h2 := must(l.AddHost(ctx, "h2"))
	must(l.Admin.CreateNetwork(ctx, api.CreateNetwork{Name: "prod", Relays: []model.RelayID{relay.ID}}))
	must(l.Admin.CreateService(ctx, "prod", api.CreateService{Name: "web"}))
	must(l.Admin.CreateService(ctx, "prod", api.CreateService{Name: "batch"}))
	grant := must(l.Admin.CreateRule(ctx, "prod", api.CreateRule{From: "web", To: api.Internet, Proto: model.TCP, Ports: model.PortRange{Lo: 80, Hi: 80}}))
	web := must(h1.Attach(ctx, "web-1", "prod", "web"))
	batch := must(h1.Attach(ctx, "batch-1", "prod", "batch"))
	for _, a := range []netip.Addr{lab.Internet4, lab.Internet6, netip.MustParseAddr("169.254.169.254"), netip.MustParseAddr("fd00:ec2::254")} {
		must(lab.Serve(l.Underlay(), netip.AddrPortFrom(a, 80), "internet"))
		must(lab.Serve(l.Underlay(), netip.AddrPortFrom(a, 22), "ssh"))
	}
	for _, a := range []netip.Addr{lab.Internet4, lab.Internet6} {
		got, err := lab.DialUntil(web.Namespace, netip.AddrPortFrom(a, 80), 10*time.Second)
		if err != nil || got != "internet" {
			t.Fatalf("web to %v:80: %q %v", a, got, err)
		}
		mustNotReach(t, web.Namespace, netip.AddrPortFrom(a, 22), "a port the grant does not name")
		mustNotReach(t, batch.Namespace, netip.AddrPortFrom(a, 80), "a workload with no grant")
	}
	for _, addr := range []netip.AddrPort{
		netip.MustParseAddrPort("169.254.169.254:80"),
		netip.MustParseAddrPort("[fd00:ec2::254]:80"),
		netip.AddrPortFrom(relay.Addr, 9092),
		netip.AddrPortFrom(relay.Addr6, 9092),
		netip.AddrPortFrom(h1.Addr, 9091),
		netip.AddrPortFrom(h2.Addr, 9091),
		netip.AddrPortFrom(h1.Addr6, 9091),
		netip.MustParseAddrPort("10.213.255.1:18443"),
	} {
		mustNotReach(t, web.Namespace, addr, "an egress link to what it must never reach")
	}
	// Taking the grant away closes the path.
	if err := l.Admin.DeleteRule(ctx, "prod", grant.ID); err != nil {
		t.Fatal(err)
	}
	deadline := time.Now().Add(10 * time.Second)
	for {
		if _, err := lab.Dial(web.Namespace, netip.AddrPortFrom(lab.Internet4, 80), time.Second); err != nil {
			break
		}
		if time.Now().After(deadline) {
			t.Fatal("the internet stayed reachable after the grant went")
		}
		time.Sleep(200 * time.Millisecond)
	}
}

// laptop registers a development machine behind gw and brings it up from
// its generated config, minting the key here as wirenetctl does.
func laptop(t *testing.T, l *lab.Lab, name string, gw model.InterfaceID, ttl time.Duration) (*lab.Laptop, api.DeviceConfig) {
	t.Helper()
	priv := must(model.NewPrivateKey(crand.Reader))
	cfg := must(l.Admin.CreateDevice(context.Background(), "prod", api.CreateDevice{Service: "dev", Gateway: gw, PublicKey: priv.Public(), TTL: ttl}))
	lp := must(l.AddLaptop(name, devconf.WGQuick(priv, cfg)))
	return lp, cfg
}

func TestADevelopmentMachineReachesServicesThroughItsGatewayAndLosesThemOnRevocation(t *testing.T) {
	l := newLab(t, "e2ek", fastClocks...)
	ctx := context.Background()
	relay := must(l.AddRelay(ctx, "r1"))
	h1 := must(l.AddHost(ctx, "h1"))
	h2 := must(l.AddGatewayHost(ctx, "h2"))
	must(l.Admin.CreateNetwork(ctx, api.CreateNetwork{Name: "prod", Relays: []model.RelayID{relay.ID}}))
	db := must(l.Admin.CreateService(ctx, "prod", api.CreateService{Name: "db"}))
	must(l.Admin.CreateService(ctx, "prod", api.CreateService{Name: "gw"}))
	must(l.Admin.CreateService(ctx, "prod", api.CreateService{Name: "dev"}))
	must(l.Admin.CreateRule(ctx, "prod", api.CreateRule{From: "dev", To: "db", Proto: model.TCP, Ports: model.PortRange{Lo: 5432, Hi: 5432}}))
	gw := must(h2.AttachGateway(ctx, "gw-1", "prod", "gw"))
	db1 := must(h1.Attach(ctx, "db-1", "prod", "db"))
	must(lab.ServeRemote(db1.Namespace, netip.AddrPortFrom(db1.Addr6, 5432)))
	must(lab.Serve(db1.Namespace, netip.AddrPortFrom(db1.Addr6, 2222), "secret"))

	lp, cfg := laptop(t, l, "lap1", gw.Interface, time.Hour)
	if cfg.DNS != gw.Addr6 || cfg.Domain != "prod.internal" {
		t.Fatalf("the config names resolver %v and domain %q", cfg.DNS, cfg.Domain)
	}
	// By name, through the gateway's resolver.
	var addrs []netip.Addr
	deadline := time.Now().Add(15 * time.Second)
	for {
		var err error
		addrs, _, err = lab.LookupAt(lp.NS, cfg.DNS, "db.prod.internal.", dnsmessage.TypeAAAA)
		if err == nil && len(addrs) == 1 {
			break
		}
		if time.Now().After(deadline) {
			t.Fatalf("the laptop never resolved db: %v %v", addrs, err)
		}
		time.Sleep(200 * time.Millisecond)
	}
	if addrs[0] != db.Addr6 {
		t.Fatalf("db resolved to %v, want %v", addrs[0], db.Addr6)
	}
	// The backend sees the laptop's own address as the source.
	got, err := lab.DialUntil(lp.NS, netip.AddrPortFrom(addrs[0], 5432), 15*time.Second)
	if err != nil || got != cfg.Addr6.String() {
		t.Fatalf("laptop to db: %q %v, want the source %v", got, err, cfg.Addr6)
	}
	mustNotReach(t, lp.NS, netip.AddrPortFrom(db1.Addr6, 2222), "a port policy does not name")
	// Laptops take replies alone: a backend cannot open a flow to one.
	must(lab.Serve(lp.NS, netip.AddrPortFrom(cfg.Addr6, 8080), "laptop"))
	mustNotReach(t, db1.Namespace, netip.AddrPortFrom(cfg.Addr6, 8080), "a backend opening a flow to a laptop")

	// A second laptop sending as the first is dropped at the gateway.
	spoof, cfg2 := laptop(t, l, "lap2", gw.Interface, time.Hour)
	if err := lab.Exec(spoof.NS, "ip", "addr", "replace", netip.PrefixFrom(cfg.Addr6, 128).String(), "dev", "wg0"); err != nil {
		t.Fatal(err)
	}
	if err := lab.Exec(spoof.NS, "ip", "addr", "del", netip.PrefixFrom(cfg2.Addr6, 128).String(), "dev", "wg0"); err != nil {
		t.Fatal(err)
	}
	mustNotReach(t, spoof.NS, netip.AddrPortFrom(db.Addr6, 5432), "one laptop sending as another")

	// A backend replacement needs no new config.
	db2 := must(h1.Attach(ctx, "db-2", "prod", "db"))
	must(lab.Serve(db2.Namespace, netip.AddrPortFrom(db2.Addr6, 5432), "db-2"))
	must(h1.Detach(ctx, db1.Interface))
	deadline = time.Now().Add(15 * time.Second)
	for {
		got, err := lab.Dial(lp.NS, netip.AddrPortFrom(db.Addr6, 5432), time.Second)
		if err == nil && got == "db-2" {
			break
		}
		if time.Now().After(deadline) {
			t.Fatalf("after the replacement the laptop reached %q (%v)", got, err)
		}
		time.Sleep(200 * time.Millisecond)
	}

	// Revocation, with no grace period.
	if err := l.Admin.Revoke(ctx, cfg.Interface); err != nil {
		t.Fatal(err)
	}
	deadline = time.Now().Add(10 * time.Second)
	for {
		if _, err := lab.Dial(lp.NS, netip.AddrPortFrom(db.Addr6, 5432), time.Second); err != nil {
			break
		}
		if time.Now().After(deadline) {
			t.Fatal("a revoked laptop still reaches db")
		}
		time.Sleep(200 * time.Millisecond)
	}
}

// TestEveryDaemonReportsWhatItDoes drives an attach, a service change, a
// relay failover and a revocation, and checks that each daemon's metrics
// move and its logs name the resources involved.
func TestEveryDaemonReportsWhatItDoes(t *testing.T) {
	l := newLab(t, "e2el", fastClocks...)
	ctx := context.Background()
	r1 := must(l.AddRelay(ctx, "r1"))
	r2 := must(l.AddRelay(ctx, "r2"))
	h1 := must(l.AddHost(ctx, "h1"))
	h2 := must(l.AddHost(ctx, "h2"))
	svc := webDB(t, l, r1, r2)
	db1 := attachDB(t, h2, "db-1")
	web := must(h1.Attach(ctx, "web-1", "prod", "web"))
	dbAddr := netip.AddrPortFrom(svc.Addr6, 5432)
	if _, err := lab.DialUntil(web.Namespace, dbAddr, 20*time.Second); err != nil {
		t.Fatal(err)
	}
	type check struct {
		url, sel string
		min      float64
	}
	expect := func(when string, checks ...check) {
		t.Helper()
		deadline := time.Now().Add(5 * time.Second)
		for _, c := range checks {
			for {
				v := metric(must(lab.Metrics(c.url)), c.sel)
				if v >= c.min {
					break
				}
				if time.Now().After(deadline) {
					t.Errorf("%s: %s = %v, want at least %v", when, c.sel, v, c.min)
					break
				}
				time.Sleep(100 * time.Millisecond)
			}
		}
	}
	cpm := l.CPTelemetry()
	expect("after an attach",
		check{h1.Telemetry, `wirenet_agent_local_calls_total{call="attach",result="ok"}`, 1},
		check{h1.Telemetry, `wirenet_agent_kernel_ops_total{kind="create_device",result="ok"}`, 1},
		check{h1.Telemetry, `wirenet_agent_kernel_op_seconds_count{kind="set_peers"}`, 1},
		check{h1.Telemetry, `wirenet_agent_convergence_seconds_count`, 1},
		check{h1.Telemetry, `wirenet_agent_registrations_total{result="sent"}`, 1},
		check{h1.Telemetry, `wirenet_agent_relay_probes_total`, 1},
		check{h1.Telemetry, `wirenet_agent_interfaces{phase="ready"}`, 1},
		check{h1.Telemetry, `wirenet_agent_namespaces{kind="named"}`, 1},
		check{h1.Telemetry, `wirenet_agent_peers`, 1},
		check{h1.Telemetry, `wirenet_agent_generation`, 1},
		check{cpm, `wirenet_cp_requests_total{code="200",route="POST /v1/agent/attach"}`, 2},
		check{cpm, `wirenet_cp_lease_events_total{event="attached"}`, 2},
		check{cpm, `wirenet_cp_store_transactions_total{op="attach",result="ok"}`, 2},
		check{cpm, `wirenet_cp_pushes_total`, 1},
		check{r1.Telemetry, `wirenet_relay_registrations_total{result="accepted"}`, 2},
		check{r1.Telemetry, `wirenet_relay_ports`, 2},
		check{r2.Telemetry, `wirenet_relay_registrations_total{result="accepted"}`, 2},
		check{r2.Telemetry, `wirenet_relay_ports`, 2},
	)
	// The one edge sends through one relay of the two.
	carrier := r1
	if metric(must(lab.Metrics(r1.Telemetry)), "wirenet_relay_forwarded_packets_total") == 0 {
		carrier = r2
	}
	expect("after an attach", check{carrier.Telemetry, `wirenet_relay_forwarded_packets_total`, 1},
		check{h1.Telemetry, fmt.Sprintf(`wirenet_agent_relay_peers{relay="%s"}`, carrier.ID), 1},
		check{h1.Telemetry, fmt.Sprintf(`wirenet_agent_relay_up{relay="%s"}`, carrier.ID), 1})
	if lines := h1.Agent.LogLines("attach"); len(lines) == 0 || lines[0]["interface"] != string(web.Interface) ||
		lines[0]["namespace"] != web.Namespace || lines[0]["network"] != string(web.Network) || lines[0]["service"] != string(web.Service) {
		t.Errorf("the agent's attach line: %v", lines)
	}
	if lines := l.CP().LogLines("interface attached"); len(lines) < 2 || lines[0]["host"] == nil || lines[0]["interface"] == nil || lines[0]["network"] == nil {
		t.Errorf("the control plane's attach lines: %v", lines)
	}
	if lines := carrier.Proc.LogLines("port table loaded"); len(lines) == 0 || lines[len(lines)-1]["generation"] == nil {
		t.Errorf("the relay's table lines: %v", lines)
	}

	// A service change rewrites the client's slot map in one transaction.
	before := metric(must(lab.Metrics(h1.Telemetry)), `wirenet_agent_nft_transaction_size_count`)
	attachDB(t, h2, "db-2")
	expect("after a service change", check{h1.Telemetry, `wirenet_agent_nft_transaction_size_count`, before + 1})

	// A failover is counted and logged.
	carrier.Kill()
	if _, _, err := timeToReach(web.Namespace, dbAddr, 15*time.Second); err != nil {
		t.Fatal(err)
	}
	expect("after a failover", check{h1.Telemetry, `wirenet_agent_core_events_total{event="failovers"}`, 1})
	if lines := h1.Agent.LogLines("relay failover"); len(lines) == 0 || lines[0]["relays_up"] == nil {
		t.Errorf("the agent's failover line: %v", lines)
	}

	// A revocation is counted at the control plane and flushes at the peer.
	flushes := metric(must(lab.Metrics(h1.Telemetry)), `wirenet_agent_kernel_ops_total{kind="flush",result="ok"}`)
	if err := l.Admin.Revoke(ctx, db1.Interface); err != nil {
		t.Fatal(err)
	}
	expect("after a revocation",
		check{cpm, `wirenet_cp_lease_events_total{event="revoked"}`, 1},
		check{h1.Telemetry, `wirenet_agent_kernel_ops_total{kind="flush",result="ok"}`, flushes + 1},
	)
	if lines := l.CP().LogLines("interface revoked"); len(lines) != 1 || lines[0]["interface"] != string(db1.Interface) {
		t.Errorf("the control plane's revocation line: %v", lines)
	}
}

// TestTrafficOutlivesTheControlPlaneAndARestartRevokesNothing stops the
// control plane for longer than a lease term: traffic continues on what
// the agents hold, and the restarted control plane holds expiry off until
// agents have renewed, so no interface is revoked.
func TestTrafficOutlivesTheControlPlaneAndARestartRevokesNothing(t *testing.T) {
	if os.Getenv("WIRENET_TEST_POSTGRES") == "" {
		t.Skip("needs a durable store: set WIRENET_TEST_POSTGRES")
	}
	l := newLab(t, "e2em", fastClocks...)
	ctx := context.Background()
	relay := must(l.AddRelay(ctx, "r1"))
	h1 := must(l.AddHost(ctx, "h1"))
	h2 := must(l.AddHost(ctx, "h2"))
	svc := webDB(t, l, relay)
	db := attachDB(t, h2, "db-1")
	web := must(h1.Attach(ctx, "web-1", "prod", "web"))
	dbAddr := netip.AddrPortFrom(svc.Addr6, 5432)
	if _, err := lab.DialUntil(web.Namespace, dbAddr, 20*time.Second); err != nil {
		t.Fatal(err)
	}
	l.CP().Stop()
	// Past a lease term with no control plane.
	time.Sleep(9 * time.Second)
	if got, err := lab.Dial(web.Namespace, dbAddr, 2*time.Second); err != nil || got != "db-1" {
		t.Fatalf("during the outage: %q %v", got, err)
	}
	if err := l.RestartCP(); err != nil {
		t.Fatal(err)
	}
	// Give the agents a renewal or two, then check nothing was revoked.
	time.Sleep(4 * time.Second)
	for _, i := range must(l.Admin.Interfaces(ctx, "prod")) {
		if (i.ID == web.Interface || i.ID == db.Interface) && i.State != api.Live {
			t.Errorf("%s is %s after the control plane returned", i.ID, i.State)
		}
	}
	if got, err := lab.Dial(web.Namespace, dbAddr, 2*time.Second); err != nil || got != "db-1" {
		t.Fatalf("after the restart: %q %v", got, err)
	}
	// Change works again.
	db2 := attachDB(t, h2, "db-2")
	if db2.Interface == "" {
		t.Fatal("no attach after the restart")
	}
}

// TestMembersResolveEachOtherAndANameFollowsItsReplacement runs a service
// whose members address each other one by one, as etcd's do: each resolves
// the others by name in both families, a replacement on another host takes
// the name with it, and the replaced holder reaches none of its peers.
func TestMembersResolveEachOtherAndANameFollowsItsReplacement(t *testing.T) {
	l := newLab(t, "e2ep", fastClocks...)
	ctx := context.Background()
	relay := must(l.AddRelay(ctx, "r1"))
	h1, h2, h3 := must(l.AddHost(ctx, "h1")), must(l.AddHost(ctx, "h2")), must(l.AddHost(ctx, "h3"))
	must(l.Admin.CreateNetwork(ctx, api.CreateNetwork{Name: "shop", Prefix4: netip.MustParsePrefix("10.102.0.0/16"), Relays: []model.RelayID{relay.ID}}))
	must(l.Admin.CreateService(ctx, "shop", api.CreateService{Name: "etcd", IPv4: true}))
	must(l.Admin.CreateService(ctx, "shop", api.CreateService{Name: "app", IPv4: true}))
	must(l.Admin.CreateRule(ctx, "shop", api.CreateRule{From: "etcd", To: "etcd", Proto: model.TCP, Ports: model.PortRange{Lo: 2380, Hi: 2380}}))
	must(l.Admin.CreateRule(ctx, "shop", api.CreateRule{From: "app", To: "etcd", Proto: model.TCP, Ports: model.PortRange{Lo: 2379, Hi: 2379}}))

	member := func(h *lab.Host, workload, name string, replace bool) api.LocalInterface {
		t.Helper()
		i, err := h.AttachMember(ctx, workload, "shop", "etcd", name, replace)
		if err != nil {
			t.Fatalf("attach %s as %s: %v", workload, name, err)
		}
		if want := name + ".etcd.shop.internal"; i.Member != want {
			t.Fatalf("%s's answer names it %q, want %q", workload, i.Member, want)
		}
		for _, a := range []netip.Addr{i.Addr6, i.Addr4} {
			must(lab.Serve(i.Namespace, netip.AddrPortFrom(a, 2380), workload))
		}
		return i
	}
	e1 := member(h1, "e1", "etcd-1", false)
	e2 := member(h2, "e2", "etcd-2", false)
	e3 := member(h3, "e3", "etcd-3", false)
	app := must(h1.Attach(ctx, "app-1", "shop", "app"))

	// resolves waits for a namespace to resolve a name to an interface's
	// addresses, and dials the name's address in each family.
	resolves := func(ns, name string, want api.LocalInterface, answers string) {
		t.Helper()
		for _, typ := range []dnsmessage.Type{dnsmessage.TypeAAAA, dnsmessage.TypeA} {
			addr := want.Addr6
			if typ == dnsmessage.TypeA {
				addr = want.Addr4
			}
			deadline := time.Now().Add(10 * time.Second)
			for {
				got, _, err := lab.Lookup(ns, name, typ)
				if err == nil && len(got) == 1 && got[0] == addr {
					break
				}
				if time.Now().After(deadline) {
					t.Fatalf("%v %s: %v %v, want %v", typ, name, got, err, addr)
				}
				time.Sleep(50 * time.Millisecond)
			}
			if answers == "" {
				continue
			}
			if got, err := lab.DialUntil(ns, netip.AddrPortFrom(addr, 2380), 10*time.Second); err != nil || got != answers {
				t.Fatalf("dialing %s at %v: %q %v, want %q", name, addr, got, err, answers)
			}
		}
	}
	resolves(e1.Namespace, "etcd-2.etcd.shop.internal.", e2, "e2")
	resolves(e1.Namespace, "etcd-3.etcd.shop.internal.", e3, "e3")
	resolves(e3.Namespace, "etcd-1.etcd.shop.internal.", e1, "e1")
	resolves(e2.Namespace, "etcd-2.etcd.shop.internal.", e2, "")
	// A client of the service resolves its members too, under the
	// service's policy: port 2379, never the members' 2380.
	resolves(app.Namespace, "etcd-1.etcd.shop.internal.", e1, "")
	for _, a := range []netip.Addr{e1.Addr6, e1.Addr4} {
		mustNotReach(t, app.Namespace, netip.AddrPortFrom(a, 2380), "app to a member's peer port")
	}

	// A held name refuses a second holder.
	if i, err := h3.AttachMember(ctx, "e2-dup", "shop", "etcd", "etcd-2", false); err == nil || !strings.Contains(err.Error(), "held by") {
		t.Fatalf("a second holder of etcd-2: %+v, %v", i, err)
	}

	// etcd-2's host is lost: its agent dies, and the old holder's device
	// keeps every peer it had. etcd-2 moves to h3. Its peers follow the
	// name, and their hosts fence the old holder: it reaches none of them,
	// and none of them reaches it.
	h2.Agent.Kill()
	start := time.Now()
	moved := member(h3, "e2-moved", "etcd-2", true)
	resolves(e1.Namespace, "etcd-2.etcd.shop.internal.", moved, "e2-moved")
	t.Logf("etcd-2 moved: e1 reached it by name %v after the replacing attach began", time.Since(start))
	resolves(e3.Namespace, "etcd-2.etcd.shop.internal.", moved, "e2-moved")
	for _, peer := range []api.LocalInterface{e1, e3} {
		for _, a := range []netip.Addr{peer.Addr6, peer.Addr4} {
			mustNotReach(t, e2.Namespace, netip.AddrPortFrom(a, 2380), "the replaced holder to a peer")
		}
	}
	for _, a := range []netip.Addr{e2.Addr6, e2.Addr4} {
		mustNotReach(t, e1.Namespace, netip.AddrPortFrom(a, 2380), "a peer to the replaced holder")
	}
	ifaces := must(l.Admin.Interfaces(ctx, "shop"))
	for _, i := range ifaces {
		if i.ID == e2.Interface && i.State != api.Revoked {
			t.Fatalf("the replaced holder is %s, want revoked", i.State)
		}
		if i.ID == moved.Interface && (i.Member != "etcd-2" || i.State != api.Live) {
			t.Fatalf("the new holder lists as %+v", i)
		}
	}
}

// TestPeersThatDialEachOtherAsTheirEdgeFormsConnectAtOnce replaces a
// member round after round while it and etcd-1 dial each other, as a
// starting etcd member and its leader do. etcd-1 dials every millisecond,
// so in some rounds both first initiations reach the relay as the edge
// forms. Crossed, each end would discard its own and both would wait
// WireGuard's 5-second retry; the relay passes one.
func TestPeersThatDialEachOtherAsTheirEdgeFormsConnectAtOnce(t *testing.T) {
	l := newLab(t, "e2eq")
	ctx := context.Background()
	relay := must(l.AddRelay(ctx, "r1"))
	hs := []*lab.Host{must(l.AddHost(ctx, "h1")), must(l.AddHost(ctx, "h2")), must(l.AddHost(ctx, "h3"))}
	must(l.Admin.CreateNetwork(ctx, api.CreateNetwork{Name: "shop", Relays: []model.RelayID{relay.ID}}))
	must(l.Admin.CreateService(ctx, "shop", api.CreateService{Name: "etcd"}))
	must(l.Admin.CreateRule(ctx, "shop", api.CreateRule{From: "etcd", To: "etcd", Proto: model.TCP, Ports: model.PortRange{Lo: 2380, Hi: 2380}}))
	member := func(h *lab.Host, workload, name string, replace bool) (api.LocalInterface, net.Listener) {
		t.Helper()
		i, err := h.AttachMember(ctx, workload, "shop", "etcd", name, replace)
		if err != nil {
			t.Fatal(err)
		}
		return i, must(lab.Serve(i.Namespace, netip.AddrPortFrom(i.Addr6, 2380), workload))
	}
	e1, _ := member(hs[0], "e1", "etcd-1", false)
	_, ln := member(hs[1], "e2-r0", "etcd-2", false)
	// etcd-1 dials etcd-2's name every millisecond, recording when each
	// holder first answers.
	var mu sync.Mutex
	reached := map[string]time.Time{}
	// The dialer ends before the test does: the lab's teardown kills
	// whatever process a namespace holds, and a dial can hold one from the
	// test binary's main thread.
	stop, stopped := make(chan struct{}), make(chan struct{})
	defer func() {
		close(stop)
		<-stopped
	}()
	go func() {
		defer close(stopped)
		for {
			select {
			case <-stop:
				return
			case <-time.After(time.Millisecond):
			}
			addrs, _, err := lab.LookupWithin(e1.Namespace, "etcd-2.etcd.shop.internal.", dnsmessage.TypeAAAA, 200*time.Millisecond)
			if err != nil || len(addrs) == 0 {
				continue
			}
			if got, err := lab.Dial(e1.Namespace, netip.AddrPortFrom(addrs[0], 2380), 300*time.Millisecond); err == nil {
				mu.Lock()
				if _, ok := reached[got]; !ok {
					reached[got] = time.Now()
				}
				mu.Unlock()
			}
		}
	}()
	at := 1
	for round := 1; round <= 40; round++ {
		ln.Close()
		at = 3 - at
		start := time.Now()
		w := fmt.Sprintf("e2-r%d", round)
		var moved api.LocalInterface
		moved, ln = member(hs[at], w, "etcd-2", true)
		// The new member dials etcd-1 at once, as a starting etcd does.
		back, _, err := timeToReach(moved.Namespace, netip.AddrPortFrom(e1.Addr6, 2380), 10*time.Second)
		if err != nil || back > 2*time.Second {
			t.Errorf("round %d: %s reached etcd-1 after %v, %v; a crossing costs 5s", round, w, back, err)
		}
		deadline := time.Now().Add(10 * time.Second)
		for {
			mu.Lock()
			first, ok := reached[w]
			mu.Unlock()
			if ok {
				if d := first.Sub(start); d > 2*time.Second {
					t.Errorf("round %d: etcd-1 reached %s after %v; a crossing costs 5s", round, w, d)
				}
				break
			}
			if time.Now().After(deadline) {
				t.Fatalf("round %d: etcd-1 never reached %s", round, w)
			}
			time.Sleep(10 * time.Millisecond)
		}
	}
	t.Logf("relay: %v initiations crossed", metric(must(lab.Metrics(relay.Telemetry)), `wirenet_relay_waiting_packets_total{outcome="crossed"}`)+
		metric(must(lab.Metrics(relay.Telemetry)), `wirenet_relay_dropped_packets_total{reason="crossed_initiation"}`))
}

// TestCoLocatedMembersThatDialEachOtherConnectAtOnce replaces a member
// round after round, beside each of two peers in turn, while it and both
// peers dial each other by name every millisecond, as etcd members do. A
// member's name answers with its interface's own address, which no slot
// carries.
func TestCoLocatedMembersThatDialEachOtherConnectAtOnce(t *testing.T) {
	l := newLab(t, "e2er")
	ctx := context.Background()
	relay := must(l.AddRelay(ctx, "r1"))
	hs := []*lab.Host{must(l.AddHost(ctx, "h1")), must(l.AddHost(ctx, "h2"))}
	must(l.Admin.CreateNetwork(ctx, api.CreateNetwork{Name: "shop", Relays: []model.RelayID{relay.ID}}))
	must(l.Admin.CreateService(ctx, "shop", api.CreateService{Name: "etcd"}))
	must(l.Admin.CreateRule(ctx, "shop", api.CreateRule{From: "etcd", To: "etcd", Proto: model.TCP, Ports: model.PortRange{Lo: 2380, Hi: 2380}}))
	member := func(h *lab.Host, workload, name string, replace bool) (api.LocalInterface, net.Listener) {
		t.Helper()
		i, err := h.AttachMember(ctx, workload, "shop", "etcd", name, replace)
		if err != nil {
			t.Fatal(err)
		}
		return i, must(lab.Serve(i.Namespace, netip.AddrPortFrom(i.Addr6, 2380), workload))
	}
	e1, _ := member(hs[0], "e1", "etcd-1", false)
	e3, _ := member(hs[1], "e3", "etcd-3", false)
	_, ln := member(hs[1], "e2-r0", "etcd-2", false)
	type end struct {
		ns, name, member string
	}
	peers := []end{{e1.Namespace, "e1", "etcd-1"}, {e3.Namespace, "e3", "etcd-3"}}
	var mu sync.Mutex
	// reached holds when one end first reached another, by their names.
	reached := map[[2]string]time.Time{}
	// dialing dials a name from ns every millisecond, up to 32 dials at
	// once, until stop closes. Every dial ends before the test does: the
	// lab's teardown kills whatever process a namespace holds, and a dial
	// can hold one from the test binary's main thread.
	var dialers, dials sync.WaitGroup
	dialing := func(stop chan struct{}, from end, name string) {
		dialers.Add(1)
		defer dialers.Done()
		inflight := make(chan struct{}, 32)
		for {
			select {
			case <-stop:
				return
			case <-time.After(time.Millisecond):
			}
			select {
			case inflight <- struct{}{}:
			default:
				continue
			}
			dials.Add(1)
			go func() {
				defer dials.Done()
				defer func() { <-inflight }()
				addrs, _, err := lab.LookupWithin(from.ns, name, dnsmessage.TypeAAAA, 200*time.Millisecond)
				if err != nil || len(addrs) == 0 {
					return
				}
				if got, err := lab.Dial(from.ns, netip.AddrPortFrom(addrs[0], 2380), 300*time.Millisecond); err == nil {
					mu.Lock()
					if k := [2]string{from.name, got}; reached[k].IsZero() {
						reached[k] = time.Now()
					}
					mu.Unlock()
				}
			}()
		}
	}
	stop := make(chan struct{})
	defer func() {
		close(stop)
		dialers.Wait()
		dials.Wait()
	}()
	for _, p := range peers {
		go dialing(stop, p, "etcd-2.etcd.shop.internal.")
	}
	// took holds each first connection's time from the attach request, by
	// whether the two ends share a host and which end dialed.
	took := map[[2]string][]time.Duration{}
	at := 1
	for round := 1; round <= 40; round++ {
		ln.Close()
		at = 1 - at
		start := time.Now()
		w := fmt.Sprintf("e2-r%d", round)
		var moved api.LocalInterface
		moved, ln = member(hs[at], w, "etcd-2", true)
		// The new member dials both peers at once, as a starting etcd does.
		mine := make(chan struct{})
		for _, p := range peers {
			go dialing(mine, end{moved.Namespace, w, "etcd-2"}, p.member+".etcd.shop.internal.")
		}
		deadline := time.Now().Add(10 * time.Second)
		for i, p := range peers {
			path := map[bool]string{true: "beside it", false: "through the relay"}[i == at]
			for _, k := range [][2]string{{p.name, w}, {w, p.name}} {
				for {
					mu.Lock()
					first := reached[k]
					mu.Unlock()
					if !first.IsZero() {
						d := first.Sub(start)
						dir := map[bool]string{true: "the peer's dial", false: "the new member's dial"}[k[1] == w]
						took[[2]string{path, dir}] = append(took[[2]string{path, dir}], d)
						if d > 2*time.Second {
							t.Errorf("round %d: %s reached %s %s after %v; a crossing costs 5s", round, k[0], k[1], path, d)
						}
						break
					}
					if time.Now().After(deadline) {
						t.Fatalf("round %d: %s never reached %s", round, k[0], k[1])
					}
					time.Sleep(10 * time.Millisecond)
				}
			}
		}
		close(mine)
	}
	for _, k := range slices.SortedFunc(maps.Keys(took), func(a, b [2]string) int { return cmp.Compare(a[0]+a[1], b[0]+b[1]) }) {
		ds := took[k]
		slices.Sort(ds)
		t.Logf("%s, %s: p50 %v, max %v over %d rounds", k[0], k[1], ds[len(ds)/2].Round(100*time.Microsecond), ds[len(ds)-1].Round(100*time.Microsecond), len(ds))
	}
}

func apiCode(err error) string {
	var ae *api.Error
	if errors.As(err, &ae) {
		return ae.Code
	}
	return ""
}

// TestAScopedHostAndAnAdminTokenStayInTheirNetworks hands a tenant an admin
// token for shop beside bank, another tenant's network on the operator's
// host. The tenant builds shop, registers a host of its own, and finds bank
// absent; its host's attach into bank leaves nothing behind; a quota
// refuses its growth; and taking shop out of its host's scope fences the
// host's workload, in each family.
func TestAScopedHostAndAnAdminTokenStayInTheirNetworks(t *testing.T) {
	l := newLab(t, "e2es", fastClocks...)
	ctx := context.Background()
	relay := must(l.AddRelay(ctx, "r1"))
	hv := must(l.AddHost(ctx, "hv"))
	for i, net := range []string{"shop", "bank"} {
		must(l.Admin.CreateNetwork(ctx, api.CreateNetwork{
			Name: net, Prefix4: netip.MustParsePrefix(fmt.Sprintf("10.%d.0.0/16", 110+i)), Relays: []model.RelayID{relay.ID},
		}))
	}
	tenant := must(l.Client(must(l.Admin.CreateAdmin(ctx, api.CreateAdmin{Name: "tenant", Networks: []string{"shop"}})).Token))
	must(tenant.CreateService(ctx, "shop", api.CreateService{Name: "web", IPv4: true}))
	db := must(tenant.CreateService(ctx, "shop", api.CreateService{Name: "db", IPv4: true}))
	must(tenant.CreateRule(ctx, "shop", api.CreateRule{From: "web", To: "db", Proto: model.TCP, Ports: model.PortRange{Lo: 5432, Hi: 5432}}))
	must(l.Admin.CreateService(ctx, "bank", api.CreateService{Name: "web", IPv4: true}))
	bankDBSvc := must(l.Admin.CreateService(ctx, "bank", api.CreateService{Name: "db", IPv4: true}))
	must(l.Admin.CreateRule(ctx, "bank", api.CreateRule{From: "web", To: "db", Proto: model.TCP, Ports: model.PortRange{Lo: 5432, Hi: 5432}}))

	if nets := must(tenant.Networks(ctx)); len(nets) != 1 || nets[0].Name != "shop" {
		t.Fatalf("the tenant lists %v", nets)
	}
	for what, err := range map[string]error{
		"a service in bank": func() error { _, err := tenant.CreateService(ctx, "bank", api.CreateService{Name: "x"}); return err }(),
		"bank's interfaces": func() error { _, err := tenant.Interfaces(ctx, "bank"); return err }(),
		"a host scoped to it": func() error {
			_, err := tenant.CreateHost(ctx, api.CreateHost{Name: "x", Networks: []string{"bank"}})
			return err
		}(),
		"a global host": func() error { _, err := tenant.CreateHost(ctx, api.CreateHost{Name: "x"}); return err }(),
	} {
		if apiCode(err) != api.CodeNotFound && apiCode(err) != api.CodeForbidden {
			t.Errorf("the tenant reached %s: %v", what, err)
		}
	}

	th := must(l.AddHostAs(ctx, tenant, "th", []string{"shop"}))
	shopDB := must(hv.Attach(ctx, "db-1", "shop", "db"))
	bankDB := must(hv.Attach(ctx, "db-2", "bank", "db"))
	for _, i := range []api.LocalInterface{shopDB, bankDB} {
		for _, a := range []netip.Addr{i.Addr6, i.Addr4} {
			must(lab.Serve(i.Namespace, netip.AddrPortFrom(a, 5432), "db"))
		}
	}
	web := must(th.Attach(ctx, "web-1", "shop", "web"))
	for _, addr := range []netip.Addr{db.Addr6, db.Addr4} {
		if _, got, err := timeToReach(web.Namespace, netip.AddrPortFrom(addr, 5432), 20*time.Second); err != nil || got != "db" {
			t.Fatalf("the tenant's web to its db at %v: %q %v", addr, got, err)
		}
	}

	// An attach into bank leaves no namespace on the tenant's host and no
	// interface in bank for bank's hosts to peer with.
	namespaces, bankIfaces := th.Namespaces(), len(must(l.Admin.Interfaces(ctx, "bank")))
	if _, err := th.Attach(ctx, "web-2", "bank", "web"); err == nil {
		t.Fatal("the tenant's host attached into bank")
	}
	if got := th.Namespaces(); !slices.Equal(got, namespaces) {
		t.Errorf("the refused attach left namespaces %v, had %v", got, namespaces)
	}
	if got := len(must(l.Admin.Interfaces(ctx, "bank"))); got != bankIfaces {
		t.Errorf("bank holds %d interfaces after the refused attach, had %d", got, bankIfaces)
	}
	for _, addr := range []netip.Addr{bankDBSvc.Addr6, bankDBSvc.Addr4, bankDB.Addr6, bankDB.Addr4} {
		mustNotReach(t, web.Namespace, netip.AddrPortFrom(addr, 5432), "bank's db from the tenant's web")
	}

	// A quota at what shop holds refuses another interface and another
	// rule, and the tenant cannot raise it.
	must(l.Admin.SetQuota(ctx, "shop", api.Quota{Interfaces: 2, Rules: 1}))
	if _, err := th.Attach(ctx, "web-3", "shop", "web"); err == nil {
		t.Error("an attach past shop's quota succeeded")
	}
	if _, err := tenant.CreateRule(ctx, "shop", api.CreateRule{From: "db", To: "web", Proto: model.TCP}); apiCode(err) != api.CodeExhausted {
		t.Errorf("a rule past shop's quota: %v", err)
	}
	if _, err := tenant.SetQuota(ctx, "shop", api.Quota{}); apiCode(err) != api.CodeForbidden {
		t.Errorf("the tenant raising its quota: %v", err)
	}
	q := must(tenant.Quota(ctx, "shop"))
	if q.Usage.Interfaces != 2 || q.Usage.Rules != 1 {
		t.Errorf("shop's usage reads %+v", q.Usage)
	}

	// Taking shop out of the host's scope revokes its workload, which
	// shop's db then refuses in each family.
	must(l.Admin.SetHostScope(ctx, "th", api.Scope{}))
	deadline := time.Now().Add(10 * time.Second)
	for {
		if _, err := lab.Dial(web.Namespace, netip.AddrPortFrom(shopDB.Addr6, 5432), time.Second); err != nil {
			break
		}
		if time.Now().After(deadline) {
			t.Fatal("the rescoped host's workload still reaches shop's db")
		}
		time.Sleep(200 * time.Millisecond)
	}
	for _, addr := range []netip.Addr{db.Addr6, db.Addr4, shopDB.Addr6, shopDB.Addr4} {
		mustNotReach(t, web.Namespace, netip.AddrPortFrom(addr, 5432), "shop's db from a host scoped out of shop")
	}
	for _, i := range must(l.Admin.Interfaces(ctx, "shop")) {
		if i.ID == web.Interface && i.State != api.Revoked {
			t.Errorf("the rescoped host's interface is %s", i.State)
		}
	}
}
