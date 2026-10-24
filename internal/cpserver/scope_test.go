package cpserver

import (
	"context"
	"encoding/json"
	"errors"
	"io"
	"net/http"
	"net/netip"
	"slices"
	"strconv"
	"strings"
	"testing"
	"time"

	"github.com/danthegoodman1/wirenet/internal/api"
	"github.com/danthegoodman1/wirenet/internal/cpclient"
	"github.com/danthegoodman1/wirenet/internal/model"
	"github.com/danthegoodman1/wirenet/internal/prng"
	"github.com/danthegoodman1/wirenet/internal/store"
	"github.com/danthegoodman1/wirenet/internal/store/locked"
	"github.com/danthegoodman1/wirenet/internal/store/mem"
)

type answer struct {
	status int
	err    api.Error
	header http.Header
	body   []byte
}

// raw calls the API with a token and a body, as no client would, so a test
// sees the answer itself.
func (e *env) raw(token, method, path, body string) answer {
	e.t.Helper()
	req, err := http.NewRequestWithContext(e.ctx, method, e.url+path, strings.NewReader(body))
	if err != nil {
		e.t.Fatal(err)
	}
	if token != "" {
		req.Header.Set("Authorization", "Bearer "+token)
	}
	resp, err := http.DefaultClient.Do(req)
	if err != nil {
		e.t.Fatal(err)
	}
	defer resp.Body.Close()
	b, err := io.ReadAll(resp.Body)
	if err != nil {
		e.t.Fatal(err)
	}
	a := answer{status: resp.StatusCode, header: resp.Header, body: b}
	if resp.StatusCode != http.StatusOK {
		json.Unmarshal(b, &a.err)
	}
	return a
}

// tenancy is a fleet of two tenants' networks: the tenant holds an admin
// token and a host scoped to shop, and bank belongs to someone else.
type tenancy struct {
	*env
	operator, tenant, globalHost, scopedHost, relay string
	shopIface, bankIface                            model.InterfaceID
}

func newTenancy(t *testing.T, st store.Store, cfg Config) *tenancy {
	e := newEnv(t, st, cfg)
	ty := &tenancy{env: e, operator: adminToken}
	rl := must(e.admin.CreateRelay(e.ctx, api.CreateRelay{
		Name: "r1", Addresses: []api.RelayAddress{{Local: netip.MustParseAddr("10.0.0.1"), Advertised: netip.MustParseAddr("10.0.0.1")}},
		PortLo: 20000, PortHi: 20999, ProbePort: 19999,
	}))
	ty.relay = rl.Token
	for _, net := range []string{"shop", "bank"} {
		must(e.admin.CreateNetwork(e.ctx, api.CreateNetwork{Name: net, Relays: []model.RelayID{model.RelayID(rl.ID)}}))
		for _, svc := range []string{"web", "db"} {
			must(e.admin.CreateService(e.ctx, net, api.CreateService{Name: svc}))
		}
	}
	ty.tenant = must(e.admin.CreateAdmin(e.ctx, api.CreateAdmin{Name: "tenant", Networks: []string{"shop"}})).Token
	ty.globalHost = must(e.admin.CreateHost(e.ctx, api.CreateHost{Name: "hv"})).Token
	ty.scopedHost = must(e.admin.CreateHost(e.ctx, api.CreateHost{Name: "tenant-host", Networks: []string{"shop"}})).Token
	must(e.admin.CreateHost(e.ctx, api.CreateHost{Name: "bank-host", Networks: []string{"bank"}}))
	hv := e.client(ty.globalHost)
	r := prng.New(7)
	ty.shopIface = must(hv.Attach(e.ctx, attachReq(t, r, "shop", "web", 40001))).Interface
	ty.bankIface = must(hv.Attach(e.ctx, attachReq(t, r, "bank", "web", 40002))).Interface
	return ty
}

// routeCall is one call on a route: in names the tenant's own network or
// what it manages, and out the same call on another tenant's, answered by
// the not-found message hidden carries. A route that names neither has no
// out.
type routeCall struct {
	class        string
	method, path string
	in, out      string
	body         string
	outBody      string
	hidden       string
}

func (ty *tenancy) calls() map[string]routeCall {
	shop, bank := string(ty.shopIface), string(ty.bankIface)
	return map[string]routeCall{
		"POST /v1/networks":                        {class: "operator", in: "/v1/networks", body: `{}`},
		"GET /v1/networks":                         {class: "admin", in: "/v1/networks"},
		"GET /v1/networks/{net}":                   {class: "admin", in: "/v1/networks/shop", out: "/v1/networks/bank", hidden: "network bank not found"},
		"DELETE /v1/networks/{net}":                {class: "operator", in: "/v1/networks/missing"},
		"GET /v1/networks/{net}/quota":             {class: "admin", in: "/v1/networks/shop/quota", out: "/v1/networks/bank/quota", hidden: "network bank not found"},
		"PUT /v1/networks/{net}/quota":             {class: "operator", in: "/v1/networks/missing/quota", body: `{}`},
		"POST /v1/networks/{net}/services":         {class: "admin", in: "/v1/networks/shop/services", out: "/v1/networks/bank/services", body: `{}`, hidden: "network bank not found"},
		"GET /v1/networks/{net}/services":          {class: "admin", in: "/v1/networks/shop/services", out: "/v1/networks/bank/services", hidden: "network bank not found"},
		"DELETE /v1/networks/{net}/services/{svc}": {class: "admin", in: "/v1/networks/shop/services/missing", out: "/v1/networks/bank/services/web", hidden: "network bank not found"},
		"POST /v1/networks/{net}/rules":            {class: "admin", in: "/v1/networks/shop/rules", out: "/v1/networks/bank/rules", body: `{"from":"web","to":"db","proto":"bogus"}`, hidden: "network bank not found"},
		"GET /v1/networks/{net}/rules":             {class: "admin", in: "/v1/networks/shop/rules", out: "/v1/networks/bank/rules", hidden: "network bank not found"},
		"DELETE /v1/networks/{net}/rules/{rule}":   {class: "admin", in: "/v1/networks/shop/rules/rule-missing", out: "/v1/networks/bank/rules/rule-missing", hidden: "network bank not found"},
		"GET /v1/networks/{net}/policy":            {class: "admin", in: "/v1/networks/shop/policy", out: "/v1/networks/bank/policy", hidden: "network bank not found"},
		"GET /v1/networks/{net}/interfaces":        {class: "admin", in: "/v1/networks/shop/interfaces", out: "/v1/networks/bank/interfaces", hidden: "network bank not found"},
		"POST /v1/interfaces/{id}/revoke":          {class: "admin", in: "/v1/interfaces/" + shop + "/revoke", out: "/v1/interfaces/" + bank + "/revoke", hidden: "interface " + bank + " not found"},
		"POST /v1/networks/{net}/devices":          {class: "admin", in: "/v1/networks/shop/devices", out: "/v1/networks/bank/devices", body: `{}`, hidden: "network bank not found"},
		"POST /v1/hosts":                           {class: "admin", in: "/v1/hosts", out: "/v1/hosts", body: `{"name":"","networks":["shop"]}`, outBody: `{"name":"x","networks":["bank"]}`, hidden: "network bank not found"},
		"GET /v1/hosts":                            {class: "admin", in: "/v1/hosts"},
		"PUT /v1/hosts/{host}/scope":               {class: "admin", in: "/v1/hosts/tenant-host/scope", out: "/v1/hosts/bank-host/scope", body: `{"networks":["shop"]}`, hidden: "host bank-host not found"},
		"DELETE /v1/hosts/{host}":                  {class: "admin", in: "/v1/hosts/missing", out: "/v1/hosts/bank-host", hidden: "host bank-host not found"},
		"POST /v1/relays":                          {class: "operator", in: "/v1/relays", body: `{}`},
		"GET /v1/relays":                           {class: "operator", in: "/v1/relays"},
		"DELETE /v1/relays/{relay}":                {class: "operator", in: "/v1/relays/missing"},
		"POST /v1/admins":                          {class: "operator", in: "/v1/admins", body: `{}`},
		"GET /v1/admins":                           {class: "operator", in: "/v1/admins"},
		"PUT /v1/admins/{admin}/scope":             {class: "operator", in: "/v1/admins/missing/scope", body: `{"networks":["shop"]}`},
		"DELETE /v1/admins/{admin}":                {class: "operator", in: "/v1/admins/missing"},
		"POST /v1/agent/attach":                    {class: "host", in: "/v1/agent/attach", body: `{}`},
		"POST /v1/agent/release":                   {class: "host", in: "/v1/agent/release", body: `{"interfaces":[]}`},
		"POST /v1/agent/renew":                     {class: "host", in: "/v1/agent/renew", body: `{"interfaces":[]}`},
		"GET /v1/agent/state":                      {class: "host", in: "/v1/agent/state?since=0"},
		"GET /v1/relay/state":                      {class: "relay", in: "/v1/relay/state?since=0"},
	}
}

// TestEveryRouteAdmitsExactlyItsPrincipals calls every route the server
// registers as every kind of principal, and checks who gets through, who is
// refused, and that a scoped admin finds another tenant's resources absent.
// A route added without a case here fails it.
func TestEveryRouteAdmitsExactlyItsPrincipals(t *testing.T) {
	eachStore(t, func(t *testing.T, open func() store.Store) {
		cfg := testConfig()
		cfg.PollTimeout = 50 * time.Millisecond
		cfg.Limits = Limits{}
		ty := newTenancy(t, open(), cfg)
		calls := ty.calls()
		var registered []string
		for _, rt := range ty.srv.routes() {
			registered = append(registered, rt.pattern)
			if _, ok := calls[rt.pattern]; !ok {
				t.Errorf("route %s has no case", rt.pattern)
			}
		}
		for pattern := range calls {
			if !slices.Contains(registered, pattern) {
				t.Errorf("case %s names no route", pattern)
			}
		}
		principals := []struct{ name, token string }{
			{"nobody", ""}, {"a wrong token", "wrong-token-0123456789"}, {"the operator", ty.operator},
			{"the tenant", ty.tenant}, {"a global host", ty.globalHost}, {"a scoped host", ty.scopedHost},
			{"a relay", ty.relay},
		}
		admitted := func(class, who string) bool {
			switch class {
			case "operator":
				return who == "the operator"
			case "admin":
				return who == "the operator" || who == "the tenant"
			case "host":
				return who == "a global host" || who == "a scoped host"
			}
			return who == "a relay"
		}
		for pattern, c := range calls {
			method, _, _ := strings.Cut(pattern, " ")
			for _, p := range principals {
				a := ty.raw(p.token, method, c.in, c.body)
				switch {
				case admitted(c.class, p.name):
					if a.status == http.StatusUnauthorized || a.status == http.StatusForbidden || c.hidden != "" && a.err.Message == c.hidden {
						t.Errorf("%s on %s: %d %+v, want it admitted", p.name, pattern, a.status, a.err)
					}
				case c.class == "operator" && p.name == "the tenant":
					if a.status != http.StatusForbidden {
						t.Errorf("%s on %s: %d %+v, want 403", p.name, pattern, a.status, a.err)
					}
				default:
					if a.status != http.StatusUnauthorized {
						t.Errorf("%s on %s: %d %+v, want 401", p.name, pattern, a.status, a.err)
					}
				}
			}
			if c.out == "" {
				continue
			}
			body := c.body
			if c.outBody != "" {
				body = c.outBody
			}
			a := ty.raw(ty.tenant, method, c.out, body)
			if a.status != http.StatusNotFound || a.err.Code != api.CodeNotFound || a.err.Message != c.hidden {
				t.Errorf("the tenant on %s outside its scope: %d %+v, want 404 %q", pattern, a.status, a.err, c.hidden)
			}
		}
	})
}

// TestAScopedAdminSeesOnlyItsNetworksAndHosts checks the lists a scoped
// admin reads.
func TestAScopedAdminSeesOnlyItsNetworksAndHosts(t *testing.T) {
	eachStore(t, func(t *testing.T, open func() store.Store) {
		ty := newTenancy(t, open(), testConfig())
		c := ty.client(ty.tenant)
		nets := must(c.Networks(ty.ctx))
		if len(nets) != 1 || nets[0].Name != "shop" {
			t.Fatalf("the tenant lists networks %v", nets)
		}
		hosts := must(c.Hosts(ty.ctx))
		if len(hosts) != 1 || hosts[0].Name != "tenant-host" || hosts[0].Scope.Global {
			t.Fatalf("the tenant lists hosts %v", hosts)
		}
		if all := must(ty.admin.Hosts(ty.ctx)); len(all) != 3 {
			t.Fatalf("the operator lists %d hosts", len(all))
		}
		ifaces := must(c.Interfaces(ty.ctx, "shop"))
		if len(ifaces) != 1 || ifaces[0].ID != ty.shopIface {
			t.Fatalf("the tenant lists interfaces %v", ifaces)
		}
	})
}

// TestOnlyTheOperatorGrantsInternetEgress checks that an admin token can
// write rules between its services and none to the internet.
func TestOnlyTheOperatorGrantsInternetEgress(t *testing.T) {
	eachStore(t, func(t *testing.T, open func() store.Store) {
		ty := newTenancy(t, open(), testConfig())
		c := ty.client(ty.tenant)
		if _, err := c.CreateRule(ty.ctx, "shop", api.CreateRule{From: "web", To: "db", Proto: model.TCP}); err != nil {
			t.Fatalf("the tenant's rule between its services: %v", err)
		}
		if _, err := c.CreateRule(ty.ctx, "shop", api.CreateRule{From: "web", To: api.Internet, Proto: model.TCP}); code(err) != api.CodeForbidden {
			t.Fatalf("the tenant's egress rule: %v", err)
		}
		egress := must(ty.admin.CreateRule(ty.ctx, "shop", api.CreateRule{From: "web", To: api.Internet, Proto: model.TCP}))
		if err := c.DeleteRule(ty.ctx, "shop", egress.ID); err != nil {
			t.Fatalf("the tenant removing the operator's egress rule: %v", err)
		}
	})
}

// TestAnAdminTokenChangedThroughOneReplicaHoldsOnTheOtherAtOnce checks that
// a rescope and a deletion need no TokenTTL to reach a replica that trusts
// the token already.
func TestAnAdminTokenChangedThroughOneReplicaHoldsOnTheOtherAtOnce(t *testing.T) {
	eachStore(t, func(t *testing.T, open func() store.Store) {
		st := open()
		cfg := testConfig()
		cfg.TokenTTL = time.Hour
		a := newTenancy(t, st, cfg)
		b := newEnv(t, st, cfg)
		tb := b.client(a.tenant)
		must(tb.Network(b.ctx, "shop"))
		must(a.admin.SetAdminScope(a.ctx, "tenant", []string{"bank"}))
		if _, err := tb.Network(b.ctx, "shop"); code(err) != api.CodeNotFound {
			t.Fatalf("the other replica after the rescope: %v", err)
		}
		must(tb.Network(b.ctx, "bank"))
		if err := a.admin.DeleteAdmin(a.ctx, "tenant"); err != nil {
			t.Fatal(err)
		}
		if _, err := tb.Network(b.ctx, "bank"); code(err) != api.CodeForbidden {
			t.Fatalf("the other replica after the deletion: %v", err)
		}
	})
}

// TestAScopedPrincipalIsLimitedAndAGlobalOneIsNot checks the write rate and
// the 429 that refuses past it, renewals exempt.
func TestAScopedPrincipalIsLimitedAndAGlobalOneIsNot(t *testing.T) {
	eachStore(t, func(t *testing.T, open func() store.Store) {
		cfg := testConfig()
		cfg.Limits = Limits{Rate: 0.5, Burst: 2}
		ty := newTenancy(t, open(), cfg)
		release := func(token string) answer { return ty.raw(token, "POST", "/v1/agent/release", `{"interfaces":[]}`) }
		for i := range 2 {
			if a := release(ty.scopedHost); a.status != http.StatusOK {
				t.Fatalf("write %d within the burst: %d %+v", i, a.status, a.err)
			}
		}
		a := release(ty.scopedHost)
		if a.status != http.StatusTooManyRequests || a.err.Code != api.CodeLimited {
			t.Fatalf("a write past the burst: %d %+v", a.status, a.err)
		}
		if secs, err := strconv.Atoi(a.header.Get("Retry-After")); err != nil || secs < 1 || secs > 2 {
			t.Fatalf("Retry-After %q", a.header.Get("Retry-After"))
		}
		if a := ty.raw(ty.scopedHost, "POST", "/v1/agent/renew", `{"interfaces":[]}`); a.status != http.StatusOK {
			t.Fatalf("a renewal past the burst: %d %+v", a.status, a.err)
		}
		for i := range 10 {
			if a := release(ty.globalHost); a.status != http.StatusOK {
				t.Fatalf("a global host's write %d: %d %+v", i, a.status, a.err)
			}
			if a := ty.raw(ty.operator, "GET", "/v1/networks", ""); a.status != http.StatusOK {
				t.Fatalf("the operator's call %d: %d", i, a.status)
			}
		}
		// The client waits out the server's answer within its timeout.
		start := time.Now()
		if err := ty.client(ty.scopedHost).Release(ty.ctx, nil); err != nil {
			t.Fatalf("a limited call through the client: %v", err)
		}
		if waited := time.Since(start); waited < 500*time.Millisecond {
			t.Fatalf("the client retried after %v", waited)
		}
		// One that cannot afford the wait answers unavailable, which an
		// agent retries.
		short, err := cpclient.New(ty.url, ty.scopedHost, cpclient.Options{Timeout: 300 * time.Millisecond})
		if err != nil {
			t.Fatal(err)
		}
		err = short.Release(ty.ctx, nil)
		if !errors.Is(err, cpclient.ErrUnavailable) || code(err) != api.CodeUnavailable {
			t.Fatalf("a limited call past the client's timeout: %v", err)
		}
	})
}

// TestTheLimiterRefillsAndBoundsCallsInFlight drives the limiter's clock by
// hand.
func TestTheLimiterRefillsAndBoundsCallsInFlight(t *testing.T) {
	l := newLimiter(Limits{Rate: 2, Burst: 3, InFlight: 2})
	p, q := principal{host: "host-a", scoped: true}, principal{host: "host-b", scoped: true}
	t0 := time.Unix(0, 0)
	var done []func()
	for i := range 2 {
		end, err := l.admit(p, true, t0)
		if err != nil {
			t.Fatalf("call %d: %v", i, err)
		}
		done = append(done, end)
	}
	if _, err := l.admit(p, false, t0); err == nil {
		t.Fatal("a third call in flight was admitted")
	}
	if _, err := l.admit(q, true, t0); err != nil {
		t.Fatalf("another principal's call: %v", err)
	}
	done[0]()
	end, err := l.admit(p, true, t0)
	if err != nil {
		t.Fatalf("a call once one ended: %v", err)
	}
	end()
	done[1]()
	_, err = l.admit(p, true, t0)
	limited, ok := errors.AsType[*errLimited](err)
	if !ok || limited.retry != 500*time.Millisecond {
		t.Fatalf("a write past the burst: %v", err)
	}
	if _, err := l.admit(p, false, t0); err != nil {
		t.Fatalf("a read past the burst: %v", err)
	}
	if _, err := l.admit(p, true, t0.Add(500*time.Millisecond)); err != nil {
		t.Fatalf("a write once a token refilled: %v", err)
	}
}

// TestARenewalPassesAFullCallCap holds a scoped host's one call slot with a
// long poll, and checks a write is refused while a renewal goes through,
// so a limit never costs a lease.
func TestARenewalPassesAFullCallCap(t *testing.T) {
	cfg := testConfig()
	cfg.Limits = Limits{InFlight: 1}
	cfg.PollTimeout = time.Minute
	ty := newTenancy(t, locked.New(mem.New()), cfg)
	ctx, cancel := context.WithCancel(ty.ctx)
	defer cancel()
	req, err := http.NewRequestWithContext(ctx, "GET", ty.url+"/v1/agent/state?since=18446744073709551615", nil)
	if err != nil {
		t.Fatal(err)
	}
	req.Header.Set("Authorization", "Bearer "+ty.scopedHost)
	go func() {
		if resp, err := http.DefaultClient.Do(req); err == nil {
			resp.Body.Close()
		}
	}()
	// The scoped host makes no other call, so the one bucket holding a
	// call is the poll's.
	waitFor(t, func() bool {
		ty.srv.limits.mu.Lock()
		defer ty.srv.limits.mu.Unlock()
		for _, b := range ty.srv.limits.by {
			if b.inFlight == 1 {
				return true
			}
		}
		return false
	})
	if a := ty.raw(ty.scopedHost, "POST", "/v1/agent/release", `{"interfaces":[]}`); a.status != http.StatusTooManyRequests {
		t.Fatalf("a write while the poll holds the only call slot: %d %+v", a.status, a.err)
	}
	if a := ty.raw(ty.scopedHost, "POST", "/v1/agent/renew", `{"interfaces":[]}`); a.status != http.StatusOK {
		t.Fatalf("a renewal while the poll holds the only call slot: %d %+v", a.status, a.err)
	}
}

// TestTheLimiterForgetsWhatHoldsNothing checks that pruning drops a bucket
// once it would have refilled and nothing runs, and keeps one that would
// not have.
func TestTheLimiterForgetsWhatHoldsNothing(t *testing.T) {
	l := newLimiter(Limits{Rate: 1, Burst: 2, InFlight: 4})
	idle, busy, spent := principal{host: "host-a", scoped: true}, principal{host: "host-b", scoped: true}, principal{host: "host-c", scoped: true}
	t0 := time.Unix(0, 0)
	end, _ := l.admit(idle, true, t0)
	end()
	if _, err := l.admit(busy, false, t0); err != nil {
		t.Fatal(err)
	}
	for range 2 {
		end, _ := l.admit(spent, true, t0.Add(500*time.Millisecond))
		end()
	}
	l.prune(t0.Add(1500 * time.Millisecond))
	if _, ok := l.by[idle]; ok {
		t.Error("an idle bucket that refilled was kept")
	}
	if _, ok := l.by[busy]; !ok {
		t.Error("a bucket with a call running was dropped")
	}
	if _, ok := l.by[spent]; !ok {
		t.Error("a bucket still refilling was dropped")
	}
}

// TestACallClockedEarlierRefillsNothing admits a write timed before the
// bucket's last, and checks the bucket's time stays where it was.
func TestACallClockedEarlierRefillsNothing(t *testing.T) {
	l := newLimiter(Limits{Rate: 1, Burst: 1})
	p := principal{host: "host-a", scoped: true}
	t0 := time.Unix(100, 0)
	if _, err := l.admit(p, true, t0); err != nil {
		t.Fatal(err)
	}
	if _, err := l.admit(p, true, t0.Add(-time.Second)); err == nil {
		t.Fatal("a write clocked before the last one found a token")
	}
	if at := l.by[p].at; !at.Equal(t0) {
		t.Fatalf("the bucket's time moved back to %v", at)
	}
}
