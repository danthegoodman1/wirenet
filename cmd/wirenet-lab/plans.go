package main

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"net/netip"
	"os"
	"path/filepath"
	"strconv"
	"strings"
	"sync"
	"time"

	"github.com/danthegoodman1/wirenet/internal/api"
	"github.com/danthegoodman1/wirenet/internal/bench"
)

// Options size a plan's run.
type Options struct {
	Duration    time.Duration
	Streams     int
	RRSize      int
	Degree      int
	ChurnDegree int
	Rounds      int
	Clients     int
	Concurrency int
	MaxIfaces   int
	Edges       int
	// MTU is the overlay MTU of every network a plan creates, and of the
	// paths plan's gateway.
	MTU int
}

func (o Options) param(name string) string {
	switch name {
	case "duration":
		return o.Duration.String()
	case "streams":
		return itoa(o.Streams)
	case "rr-size":
		return itoa(o.RRSize) + "B"
	case "degree":
		return itoa(o.Degree)
	case "churn-degree":
		return itoa(o.ChurnDegree)
	case "rounds":
		return itoa(o.Rounds)
	case "clients":
		return itoa(o.Clients)
	case "concurrency":
		return itoa(o.Concurrency)
	case "max-interfaces":
		return itoa(o.MaxIfaces)
	case "edges":
		return itoa(o.Edges)
	case "mtu":
		return itoa(o.MTU)
	}
	return "?"
}

// plan is one named benchmark.
type plan struct {
	name  string
	about string
	// fleet is whether the plan needs the daemons running.
	fleet  bool
	params []string
	run    func(*run) error
}

var plans = []plan{
	{"hostbench", "cmd/hostbench on each agent host: device placement, netdev and peer concurrency, peer costs",
		false, nil, planHostbench},
	{"paths", "the plain-TCP ceiling, then the relay and a WireGuard-terminating gateway on the same middle box: throughput, middle-box CPU, round trips idle and loaded",
		true, []string{"duration", "streams", "rr-size", "mtu"}, planPaths},
	{"attach", "attach to first connection at a policy degree, timed from the attach request",
		true, []string{"degree", "rounds"}, planAttach},
	{"churn", "sustained attach-and-detach on every host at once, every pair counted",
		true, []string{"duration", "concurrency", "churn-degree"}, planChurn},
	{"converge", "replace a service's backend under churn and time until every client's new connections reach the new one",
		true, []string{"clients", "concurrency"}, planConverge},
	{"failover", "kill the relay an edge sends through, mid-flow: the established flow's stall and a new connection's wait",
		true, []string{"rounds"}, planFailover},
	{"density", "interfaces on one host until an attach fails, attach latency degrades, or the cap",
		true, []string{"max-interfaces"}, planDensity},
	{"spread", "many edges streaming at once through one relay, then two, then three: aggregate throughput and relay CPU by relay count",
		true, []string{"duration", "edges", "mtu"}, planSpread},
	{"policy", "open a service to every other with a wildcard, then time a deny closing it to one service's clients, and the deny's removal",
		true, []string{"clients"}, planPolicy},
	{"members", "a three-member etcd cluster in one service, each member holding its name; move one member to another host each round, timing its name, health and catching up, and checking the replaced holder reaches no peer",
		true, []string{"rounds"}, planMembers},
	{"scopes", "a scoped host and admin token beside another network: what each reaches, a host's attach while global against while scoped, the operator's admin calls against a scoped token's, a quota's refusal, and a burst past the limits",
		true, []string{"degree", "rounds"}, planScopes},
}

func findPlans(spec string) ([]plan, error) {
	if spec == "all" {
		return plans, nil
	}
	var out []plan
	for _, name := range strings.Split(spec, ",") {
		found := false
		for _, p := range plans {
			if p.name == name {
				out = append(out, p)
				found = true
			}
		}
		if !found {
			return nil, fmt.Errorf("no plan %q; wirenet-lab plans lists them", name)
		}
	}
	return out, nil
}

// run is one plan's run against an environment.
type run struct {
	ctx   context.Context
	env   Env
	o     Options
	rep   *Report
	log   io.Writer
	logMu sync.Mutex
	mu    sync.Mutex
	stops []Stopper
}

// logTailer is an environment that can show its daemons' logs.
type logTailer interface{ Logs(lines int) string }

// runPlan brings a fresh fleet up, runs p, and writes its report. It
// fails when the plan aborts or any assertion fails.
func runPlan(ctx context.Context, env Env, p plan, o Options, reports string, log io.Writer) error {
	rep := &Report{Plan: p.name, Env: env.Name(), Started: time.Now(), Params: map[string]string{}, Data: map[string]any{}}
	for _, k := range p.params {
		rep.Params[k] = o.param(k)
	}
	r := &run{ctx: ctx, env: env, o: o, rep: rep, log: log}
	r.logf("%s: bringing the %s environment up", p.name, env.Name())
	err := env.Up(ctx, p.fleet)
	if err == nil {
		if rep.Substrate, err = env.Substrate(ctx); err == nil {
			r.logf("%s: running", p.name)
			err = p.run(r)
		}
	}
	r.stopAll()
	if err != nil {
		rep.Failures = append(rep.Failures, "the plan stopped: "+err.Error())
		r.logf("%s: %v", p.name, err)
	}
	if t, ok := env.(logTailer); ok && len(rep.Failures) > 0 {
		rep.Raw = append(rep.Raw, Raw{Title: "Daemon logs", Text: t.Logs(30)})
	}
	if derr := env.Down(context.WithoutCancel(ctx)); derr != nil {
		rep.Failures = append(rep.Failures, "tearing down: "+derr.Error())
	}
	rep.Seconds = time.Since(rep.Started).Seconds()
	if env.DryRun() {
		if err != nil {
			return fmt.Errorf("%s: the dry run stopped: %w", p.name, err)
		}
		r.logf("%s: dry run complete; the report would read:\n%s", p.name, rep.Markdown())
		return nil
	}
	file, werr := rep.Write(reports)
	if werr != nil {
		return errors.Join(werr, err)
	}
	r.logf("%s: report in %s", p.name, file)
	if len(rep.Failures) > 0 {
		return fmt.Errorf("%s: %d assertion(s) failed: %s", p.name, len(rep.Failures), strings.Join(rep.Failures, "; "))
	}
	return nil
}

func (r *run) logf(format string, a ...any) {
	r.logMu.Lock()
	defer r.logMu.Unlock()
	fmt.Fprintf(r.log, "wirenet-lab: "+format+"\n", a...)
}

// check records a failed assertion. A dry run asserts nothing, since its
// results are stand-ins.
func (r *run) check(ok bool, format string, a ...any) bool {
	if ok || r.env.DryRun() {
		return true
	}
	msg := fmt.Sprintf(format, a...)
	r.mu.Lock()
	r.rep.Failures = append(r.rep.Failures, msg)
	r.mu.Unlock()
	r.logf("FAILED: %s", msg)
	return false
}

// data keeps a raw result in the JSON report.
func (r *run) data(key string, v any) {
	r.mu.Lock()
	defer r.mu.Unlock()
	r.rep.Data[key] = v
}

func (r *run) decode(b []byte, v any) error {
	if v == nil {
		return nil
	}
	if err := json.Unmarshal(b, v); err != nil && !r.env.DryRun() {
		if len(b) > 300 {
			b = b[:300]
		}
		return fmt.Errorf("decoding %q: %w", b, err)
	}
	return nil
}

// bench runs wirenet-bench on n and decodes its JSON into v.
func (r *run) bench(n Node, v any, args ...string) error {
	out, err := r.env.Exec(r.ctx, n, append([]string{r.env.Bin("wirenet-bench")}, args...)...)
	if err != nil {
		return err
	}
	return r.decode(out, v)
}

// ctl runs wirenetctl and decodes its JSON into v.
func (r *run) ctl(n Node, v any, args ...string) error {
	out, err := r.env.Ctl(r.ctx, n, args...)
	if err != nil {
		return err
	}
	return r.decode(out, v)
}

// spawn starts a background process that the run stops at its end.
func (r *run) spawn(n Node, argv ...string) (Stopper, error) {
	s, err := r.env.Spawn(r.ctx, n, argv...)
	if err != nil {
		return nil, err
	}
	r.mu.Lock()
	r.stops = append(r.stops, s)
	r.mu.Unlock()
	return s, nil
}

func (r *run) stopAll() {
	r.mu.Lock()
	stops := r.stops
	r.stops = nil
	r.mu.Unlock()
	for i := len(stops) - 1; i >= 0; i-- {
		if err := stops[i].Stop(context.WithoutCancel(r.ctx)); err != nil {
			r.logf("stopping a background process: %v", err)
		}
	}
}

// serve starts wirenet-bench serve on n, in namespace ns when set.
func (r *run) serve(n Node, ns string, addr netip.AddrPort, name string) (Stopper, error) {
	return r.spawn(n, r.env.Bin("wirenet-bench"), "serve", "--listen", addr.String(), "--netns="+ns, "--name", name)
}

// reach waits until a connection from ns on n reaches target.
func (r *run) reach(n Node, ns string, target netip.AddrPort, until time.Duration) (bench.Dial, error) {
	var d bench.Dials
	if err := r.bench(n, &d, "dial", "--target", target.String(), "--netns="+ns, "--until", until.String()); err != nil {
		return bench.Dial{}, err
	}
	if r.env.DryRun() {
		return bench.Dial{Reached: true}, nil
	}
	if len(d.Results) != 1 || !d.Results[0].Reached {
		return bench.Dial{}, fmt.Errorf("%s (namespace %q) did not reach %v within %v: %+v", n.Name, ns, target, until, d.Results)
	}
	return d.Results[0], nil
}

// network creates a network over relays, with services, and rules that
// let each pair's first reach its second on wirenet-bench's port.
func (r *run) network(name string, relays []Node, services []string, rules ...[2]string) (map[string]api.ServiceInfo, error) {
	var names []string
	for _, n := range relays {
		names = append(names, n.Name)
	}
	cp := r.env.CP()
	if err := r.ctl(cp, nil, "network", "create", name, "--relays", strings.Join(names, ","), "--mtu", itoa(r.o.MTU)); err != nil {
		return nil, err
	}
	out := map[string]api.ServiceInfo{}
	for _, s := range services {
		var info api.ServiceInfo
		if err := r.ctl(cp, &info, "service", "create", name, s); err != nil {
			return nil, err
		}
		out[s] = info
	}
	for _, rule := range rules {
		if err := r.ctl(cp, nil, "rule", "create", name, rule[0], rule[1], "--proto", "tcp", "--ports", strconv.Itoa(bench.Port)); err != nil {
			return nil, err
		}
	}
	return out, nil
}

// attach attaches a workload on n through its agent.
func (r *run) attach(n Node, name, network, service string) (api.LocalInterface, error) {
	var li api.LocalInterface
	err := r.ctl(n, &li, "attach", name, network, service)
	return li, err
}

// ceiling measures plain TCP between the first two hosts' own addresses,
// with no WireGuard on the path, and records it in the report.
func (r *run) ceiling(streams int, d time.Duration) (bench.Stream, error) {
	hs := r.env.Hosts()
	a, b := hs[0], hs[1]
	to := netip.AddrPortFrom(b.Addr, bench.Port)
	srv, err := r.serve(b, "", to, b.Name)
	if err != nil {
		return bench.Stream{}, err
	}
	defer srv.Stop(r.ctx)
	if _, err := r.reach(a, "", to, 10*time.Second); err != nil {
		return bench.Stream{}, err
	}
	var s bench.Stream
	if err := r.bench(a, &s, "stream", "--target", to.String(), "--duration", d.String(), "--parallel", itoa(streams)); err != nil {
		return s, err
	}
	r.setCeiling(a, b, s)
	return s, nil
}

func (r *run) setCeiling(a, b Node, s bench.Stream) {
	if c := r.rep.Ceiling; c == nil || s.BitsPerSecond > c.BitsPerSecond {
		r.rep.Ceiling = &Ceiling{From: a.Name, To: b.Name, Streams: s.Parallel, BitsPerSecond: s.BitsPerSecond, Retransmits: s.Retransmits}
	}
}

// windowLead is how far ahead a shared window starts, so every command
// that measures it arrives and connects first.
const windowLead = 3 * time.Second

// startAt is the start of a window every stream and CPU sample in it
// shares, for wirenet-bench's --at.
func startAt() string { return time.Now().Add(windowLead).UTC().Format(time.RFC3339Nano) }

// quickCeiling is the ceiling every plan records: a short run of the
// configured stream count.
func (r *run) quickCeiling() error {
	_, err := r.ceiling(r.o.Streams, min(r.o.Duration, 5*time.Second))
	return err
}

// metric sums the samples of every series whose name and labels begin
// with sel in n's metrics.
func (r *run) metric(n Node, sel string) (float64, error) {
	text, err := r.env.Metrics(r.ctx, n)
	if err != nil {
		return 0, err
	}
	return sumMetric(text, sel), nil
}

func sumMetric(text, sel string) float64 {
	var sum float64
	prefix := strings.TrimSuffix(sel, "}")
	for _, line := range strings.Split(text, "\n") {
		if strings.HasPrefix(line, "#") || !strings.HasPrefix(line, prefix) {
			continue
		}
		// The selector must end at a name or label boundary.
		if rest := line[len(prefix):]; !strings.HasPrefix(rest, " ") && !strings.HasPrefix(rest, "{") && !strings.HasPrefix(rest, ",") && !strings.HasPrefix(rest, "}") {
			continue
		}
		f := strings.Fields(line)
		if v, err := strconv.ParseFloat(f[len(f)-1], 64); err == nil {
			sum += v
		}
	}
	return sum
}

// series returns every series of the named metrics in n's metrics, keyed
// by the series as written.
func (r *run) series(n Node, names ...string) (map[string]float64, error) {
	text, err := r.env.Metrics(r.ctx, n)
	if err != nil {
		return nil, err
	}
	out := map[string]float64{}
	for _, line := range strings.Split(text, "\n") {
		f := strings.Fields(line)
		if len(f) != 2 || strings.HasPrefix(line, "#") {
			continue
		}
		for _, name := range names {
			if f[0] == name || strings.HasPrefix(f[0], name+"{") {
				if v, err := strconv.ParseFloat(f[1], 64); err == nil {
					out[f[0]] = v
				}
			}
		}
	}
	return out, nil
}

// relayTable reports how a relay's drop and registration counters moved
// between two readings.
func (r *run) relayTable(n Node, title string, before, after map[string]float64) {
	t := Table{Title: title, Columns: []string{"Counter", "Change"}}
	for _, k := range sortedKeys(after) {
		if d := after[k] - before[k]; d != 0 {
			t.Rows = append(t.Rows, []string{"`" + k + "`", num(d, 0)})
		}
	}
	if len(t.Rows) == 0 {
		t.Rows = append(t.Rows, []string{"every drop and registration counter", "0"})
	}
	t.Caption = "Read from " + n.Name + "'s metrics, and its kernel's /proc/net/snmp UDP counters, before and after."
	r.rep.table(t)
}

// udpCounters reads the UDP counters of n's own namespace from
// /proc/net/snmp, keyed "udp NoPorts" and so on: datagrams the kernel
// dropped before any socket saw them.
func (r *run) udpCounters(n Node) (map[string]float64, error) {
	out, err := r.env.Exec(r.ctx, n, "cat", "/proc/net/snmp")
	if err != nil {
		return nil, err
	}
	var names []string
	counters := map[string]float64{}
	for _, line := range strings.Split(string(out), "\n") {
		f := strings.Fields(line)
		if len(f) == 0 || f[0] != "Udp:" {
			continue
		}
		if names == nil {
			names = f
			continue
		}
		for i, name := range names[1:] {
			switch name {
			case "NoPorts", "InErrors", "RcvbufErrors", "InCsumErrors":
				if v, err := strconv.ParseFloat(f[i+1], 64); err == nil {
					counters["udp "+name] = v
				}
			}
		}
	}
	return counters, nil
}

// relayReadings reads a relay's drop and registration counters and its
// machine's UDP drops.
func (r *run) relayReadings(n Node) (map[string]float64, error) {
	m, err := r.series(n, relayCounters...)
	if err != nil {
		return nil, err
	}
	udp, err := r.udpCounters(n)
	if err != nil {
		return nil, err
	}
	for k, v := range udp {
		m[k] = v
	}
	return m, nil
}

// relayCounters are the counters relayTable reports.
var relayCounters = []string{"wirenet_relay_dropped_packets_total", "wirenet_relay_registrations_total", "wirenet_relay_write_failed_packets_total"}

// together runs fns at once and joins their errors.
func together(fns ...func() error) error {
	errs := make([]error, len(fns))
	var wg sync.WaitGroup
	for i, fn := range fns {
		wg.Go(func() { errs[i] = fn() })
	}
	wg.Wait()
	return errors.Join(errs...)
}

// sleep waits d, or less if the run is cancelled.
func (r *run) sleep(d time.Duration) {
	if r.env.DryRun() {
		return
	}
	select {
	case <-r.ctx.Done():
	case <-time.After(d):
	}
}

func port(a netip.Addr) netip.AddrPort { return netip.AddrPortFrom(a, bench.Port) }

// writeFileUnderSudo writes a file the invoking user owns.
func writeFileUnderSudo(name string, b []byte) error {
	if err := os.MkdirAll(filepath.Dir(name), 0o755); err != nil {
		return err
	}
	if err := os.WriteFile(name, b, 0o644); err != nil {
		return err
	}
	chownToInvoker(name)
	return nil
}
