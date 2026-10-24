package main

import (
	"fmt"
	"time"

	"github.com/danthegoodman1/wirenet/internal/api"
	"github.com/danthegoodman1/wirenet/internal/bench"
)

// scopeRounds bounds the rounds of each kind. A round's writes, an attach,
// a detach and a rule's creation and deletion, come slower than a scoped
// principal's default rate, so the limiter never shapes a figure.
const scopeRounds = 30

// limited429 selects the control plane's refusals over a limit.
const limited429 = `wirenet_cp_requests_total{code="429"`

// planScopes gives a tenant an admin token for one network beside another
// and scopes a host to it. It checks what each reaches, then times what
// the checks cost, round by round in turn: the host's attaches while global
// against its attaches while scoped, and the operator's admin calls against
// the scoped token's. The timed rounds stay within the scoped limits,
// which the plan checks refused nothing; a last burst past them records
// the rate a scoped token sustains.
func planScopes(r *run) error {
	if err := r.quickCeiling(); err != nil {
		return err
	}
	hs := r.env.Hosts()
	a, others := hs[0], hs[1:]
	cp := r.env.CP()
	svcs, err := r.network("scopes", r.env.Relays()[:1], []string{"peer", "new"}, [2]string{"new", "peer"})
	if err != nil {
		return err
	}
	if _, err := r.network("other", r.env.Relays()[:1], []string{"peer", "new"}, [2]string{"new", "peer"}); err != nil {
		return err
	}
	if _, err := r.spreadAttach(others, "peer", "scopes", "peer", r.o.Degree, true); err != nil {
		return err
	}
	if _, err := r.spreadAttach(others, "other-peer", "other", "peer", 1, true); err != nil {
		return err
	}
	var tenant api.Credentials
	if err := r.ctl(cp, &tenant, "admin", "create", "tenant", "--network", "scopes"); err != nil {
		return err
	}
	url, operator := r.env.OperatorAPI()
	to := port(svcs["peer"].Addr6)
	rounds := min(r.o.Rounds, scopeRounds)
	attachRound := func(name string) (bench.AttachRound, error) {
		var res bench.Attach
		err := r.bench(a, &res, "agent", "attach", "--socket", r.env.AgentSocket(a), "--network", "scopes", "--service", "new",
			"--name", name, "--rounds", "1", "--dial", to.String(), "--until", "30s", "--detach")
		if err != nil || r.env.DryRun() {
			return bench.AttachRound{}, err
		}
		if !r.check(len(res.Rounds) == 1 && res.Reached == 1, "%s never reached a peer: %+v", name, res.Rounds) {
			return bench.AttachRound{}, nil
		}
		return res.Rounds[0], nil
	}
	apiRound := func(who string, port int, token ...string) (bench.API, error) {
		var res bench.API
		args := append([]string{"api", "--cp", url, "--network", "scopes", "--hidden", "other", "--rounds", "1", "--port", itoa(port)}, token...)
		err := r.bench(cp, &res, args...)
		r.check(res.Failures == 0 && res.Limited == 0, "%s's admin calls: %d failed, %d limited", who, res.Failures, res.Limited)
		return res, err
	}
	scoped := false
	scope := func(want bool) error {
		if want == scoped {
			return nil
		}
		args := []string{"host", "scope", a.Name, "--global"}
		if want {
			args = []string{"host", "scope", a.Name, "--network", "scopes"}
		}
		scoped = want
		return r.ctl(cp, nil, args...)
	}
	if _, err := attachRound("warm"); err != nil {
		return err
	}
	if err := scope(true); err != nil {
		return err
	}
	_, err = r.attach(a, "stray", "other", "new")
	r.check(err != nil, "a host scoped to one network attached into another")
	refusedBefore, err := r.metric(cp, limited429)
	if err != nil {
		return err
	}

	res := scopeResults{Rounds: rounds}
	defer func() { r.scopesTables(res) }()
	r.logf("scopes: %d rounds of each, global and scoped in turn", rounds)
	// Attach latency climbs through a run as detached interfaces drain, so
	// rounds go global, scoped, scoped, global, and each kind takes as many
	// early rounds as late ones and as many first calls after a rescope.
	for i := range 2 * rounds {
		inScope := i%4 == 1 || i%4 == 2
		if err := scope(inScope); err != nil {
			return err
		}
		rd, err := attachRound(fmt.Sprintf("round-%d", i))
		if err != nil {
			return err
		}
		who, token := "the operator", operator
		if inScope {
			who, token = "the tenant", []string{"--token", tenant.Token}
		}
		call, err := apiRound(who, 20000+i, token...)
		if err != nil {
			return err
		}
		if inScope {
			res.Scoped, res.Tenant = append(res.Scoped, rd), append(res.Tenant, call)
			r.check(call.Hidden == 404, "the tenant read another tenant's network with status %d, want 404", call.Hidden)
		} else {
			res.Global, res.Operator = append(res.Global, rd), append(res.Operator, call)
			r.check(call.Hidden == 200, "the operator read another network with status %d", call.Hidden)
		}
	}
	if err := scope(false); err != nil {
		return err
	}
	refusedAfter, err := r.metric(cp, limited429)
	if err != nil {
		return err
	}
	r.check(refusedAfter == refusedBefore, "the limiter refused %v calls while the plan timed", refusedAfter-refusedBefore)

	// A quota at what the network holds refuses the next attach.
	var q api.QuotaInfo
	if err := r.ctl(cp, &q, "quota", "show", "scopes"); err != nil {
		return err
	}
	if err := r.ctl(cp, nil, "quota", "set", "scopes", "--interfaces", itoa(max(q.Usage.Interfaces, 1))); err != nil {
		return err
	}
	_, err = r.attach(a, "past-quota", "scopes", "new")
	r.check(err != nil, "an attach past the network's quota succeeded")
	restore := []string{"quota", "set", "scopes", "--interfaces", itoa(q.Quota.Interfaces), "--services", itoa(q.Quota.Services),
		"--rules", itoa(q.Quota.Rules), "--edges", itoa(q.Quota.Edges)}
	if err := r.ctl(cp, nil, restore...); err != nil {
		return err
	}

	// From a full bucket, the scoped token's writes spend its burst, then
	// come back at its rate.
	r.logf("scopes: %v of writes past the tenant's limits", burstWindow)
	r.sleep(burstRefill)
	burst := bench.API{}
	if err := r.bench(cp, &burst, "api", "--cp", url, "--network", "scopes", "--duration", burstWindow.String(), "--port", "40000", "--token", tenant.Token); err != nil {
		return err
	}
	r.check(burst.Limited > 0, "%d writes past the limits were never refused", burst.Writes)
	r.check(burst.Failures == 0, "%d of the burst's calls failed other than by the limit", burst.Failures)
	res.Burst = &burst
	return nil
}

// burstRefill outlasts the time a scoped principal's bucket takes to fill
// from empty at the default rate, and burstWindow is how long the burst
// runs: its second half comes after any burst is spent.
const (
	burstRefill = 6 * time.Second
	burstWindow = 12 * time.Second
)

// scopeResults are the plan's figures.
type scopeResults struct {
	Rounds   int                 `json:"rounds"`
	Global   []bench.AttachRound `json:"global"`
	Scoped   []bench.AttachRound `json:"scoped"`
	Operator []bench.API         `json:"operator"`
	Tenant   []bench.API         `json:"tenant"`
	Burst    *bench.API          `json:"burst,omitempty"`
}

func (r *run) scopesTables(res scopeResults) {
	r.data("scopes", res)
	attach := Table{
		Title:   fmt.Sprintf("Attach to first connection, one host global and then scoped, degree %d", r.o.Degree),
		Columns: []string{"The host's scope", "Rounds", "Attach p50", "p90", "max", "First connection p50", "p90", "max"},
	}
	for _, row := range []struct {
		name   string
		rounds []bench.AttachRound
	}{{"global", res.Global}, {"scoped to the network", res.Scoped}} {
		var att, first []time.Duration
		for _, rd := range row.rounds {
			att, first = append(att, fromMS(rd.AttachMS)), append(first, fromMS(rd.FirstConn))
		}
		at, fc := bench.Summarize(att), bench.Summarize(first)
		attach.Rows = append(attach.Rows, []string{row.name, itoa(at.Count), msec(at.P50), msec(at.P90), msec(at.Max), msec(fc.P50), msec(fc.P90), msec(fc.Max)})
	}
	attach.Caption = fmt.Sprintf("%d rounds of each on one host, in the order global, scoped, scoped, global, repeated: attach latency climbs through a run "+
		"as detached interfaces drain, and the order gives each kind as many early rounds as late ones. Times run from the local API request; "+
		"a scoped host's attach checks the host record the attach reads anyway.", res.Rounds)
	r.rep.table(attach)

	calls := Table{
		Title:   "Admin calls, the operator against a scoped admin token",
		Columns: []string{"Token", "Rounds", "Read p50", "p90", "Rule create p50", "p90", "Rule delete p50", "p90"},
	}
	for _, row := range []struct {
		name string
		runs []bench.API
	}{{"the operator", res.Operator}, {"scoped admin", res.Tenant}} {
		pooled := map[string][]time.Duration{}
		for _, run := range row.runs {
			for call, ms := range run.Samples {
				for _, v := range ms {
					pooled[call] = append(pooled[call], fromMS(v))
				}
			}
		}
		read, create, del := bench.Summarize(pooled["read"]), bench.Summarize(pooled["create"]), bench.Summarize(pooled["delete"])
		calls.Rows = append(calls.Rows, []string{row.name, itoa(read.Count), msec(read.P50), msec(read.P90), msec(create.P50), msec(create.P90), msec(del.P50), msec(del.P90)})
	}
	calls.Caption = "From the control-plane machine, one round after each attach and in the same order, the operator's beside the global host's " +
		"and the scoped token's beside the scoped host's. Each round reads the network, then creates a rule between two of its services and " +
		"deletes it. A scoped token's call reads its admin record in its own transaction."
	r.rep.table(calls)

	if b := res.Burst; b != nil && b.Seconds > 0 {
		half := b.Seconds / 2
		var first, second int
		for _, at := range b.Answered {
			if at < half {
				first++
			} else {
				second++
			}
		}
		r.rep.table(Table{
			Title:   "A scoped admin token past its limits",
			Columns: []string{"Writes sent", "Refused with 429", "Answered", "Answered in the first half", "Answered a second over the second half"},
			Rows: [][]string{{itoa(b.Writes), itoa(b.Limited), itoa(len(b.Answered)), itoa(first),
				fmt.Sprintf("%.1f", float64(second)/(b.Seconds-half))}},
			Caption: fmt.Sprintf("Back-to-back rule creates and deletes for %.1fs from a full bucket, a refused create skipping its delete, against the "+
				"control plane's default of 10 writes a second with a burst of 50. The first half spends the burst; the second shows the rate.", b.Seconds),
		})
	}
}

func fromMS(ms float64) time.Duration { return time.Duration(ms * float64(time.Millisecond)) }
