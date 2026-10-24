// Package cpserver serves the control plane's HTTP API over a store: the
// operator's resources, the agents' attach, release, renew and long poll,
// and the relays' long poll. The decisions are cp.Plane's; this package
// authenticates callers, runs each decision in a transaction, wakes the
// long polls a commit touches, and runs the sweeps that expire leases.
package cpserver

import (
	"context"
	"crypto/rand"
	"crypto/subtle"
	"encoding/json"
	"errors"
	"fmt"
	"net"
	"net/http"
	"strconv"
	"strings"
	"sync"
	"time"

	"github.com/prometheus/client_golang/prometheus"
	"github.com/rs/zerolog"

	"github.com/danthegoodman1/wirenet/internal/api"
	"github.com/danthegoodman1/wirenet/internal/cp"
	"github.com/danthegoodman1/wirenet/internal/model"
	"github.com/danthegoodman1/wirenet/internal/store"
)

// Config holds what a server needs beyond its store.
type Config struct {
	Plane cp.Config
	// AdminToken is the operator's token, the one global admin.
	AdminToken string
	// PollTimeout is how long a long poll parks before answering with what
	// is current.
	PollTimeout time.Duration
	// SweepEvery is how often the server heartbeats and sweeps leases.
	SweepEvery time.Duration
	// CensusEvery is how often the server counts its pools for metrics.
	CensusEvery time.Duration
	// CacheNetworks bounds how many compiled networks stay cached.
	CacheNetworks int
	// TokenTTL is how long a replica trusts a token it has looked up. A
	// host or relay deleted through another replica keeps its token
	// working here for up to this long; an admin token stops at once,
	// since every call reads its record.
	TokenTTL time.Duration
	// Limits bound each scoped principal's calls.
	Limits Limits
}

// DefaultConfig returns production settings around an admin token.
func DefaultConfig(adminToken string) Config {
	return Config{
		Plane:         cp.DefaultConfig(),
		AdminToken:    adminToken,
		PollTimeout:   25 * time.Second,
		SweepEvery:    time.Second,
		CensusEvery:   15 * time.Second,
		CacheNetworks: 4096,
		TokenTTL:      10 * time.Second,
		Limits:        DefaultLimits(),
	}
}

// Watcher is a store that reports commits made through any handle, so
// every replica wakes its long polls for the others' writes. pgstore is
// one.
type Watcher interface {
	// Watch delivers each commit's change until ctx ends or the feed
	// breaks, then closes the channel. Changes may go unseen across a
	// break, so a caller that watches again re-reads what it serves.
	Watch(ctx context.Context) (<-chan store.Change, error)
}

// Server is one control-plane replica. Replicas share a store; a store
// that implements Watcher wakes each replica's polls for the others'
// commits.
type Server struct {
	cfg   Config
	store store.Store
	plane *cp.Plane
	cache *lockedCache
	hub   *hub
	log   zerolog.Logger
	m     *metrics
	now   func() time.Time

	tokens sync.Map // [32]byte -> cachedToken, positive lookups only
	limits *limiter
}

// principal is who a call comes from: the operator, an admin token, a host
// or a relay.
type principal struct {
	operator bool
	admin    model.AdminID
	host     model.HostID
	relay    model.RelayID
	// scoped marks a principal the limits bound: an admin token, or a host
	// whose scope was not global when its token was looked up.
	scoped bool
}

// cachedToken is a token's principal, trusted until a time.
type cachedToken struct {
	p     principal
	until time.Time
}

// New returns a server. Call Run to boot it and serve its background work.
func New(cfg Config, st store.Store, log zerolog.Logger, reg prometheus.Registerer) (*Server, error) {
	if err := cfg.Plane.Validate(); err != nil {
		return nil, err
	}
	if len(cfg.AdminToken) < 16 {
		return nil, errors.New("admin token must be at least 16 characters")
	}
	if err := cfg.Limits.validate(); err != nil {
		return nil, err
	}
	if cfg.SweepEvery <= 0 || cfg.CensusEvery <= 0 {
		return nil, errors.New("sweep and census intervals must be positive")
	}
	s := &Server{
		cfg:    cfg,
		store:  st,
		plane:  &cp.Plane{Config: cfg.Plane, Rand: rand.Reader},
		cache:  &lockedCache{lru: cp.NewLRU(cfg.CacheNetworks)},
		hub:    newHub(),
		log:    log,
		now:    time.Now,
		limits: newLimiter(cfg.Limits),
	}
	s.m = newMetrics(reg, s.hub)
	return s, nil
}

// Run boots the plane and runs heartbeats, sweeps, the census and the
// store's change feed until ctx ends.
func (s *Server) Run(ctx context.Context) error {
	var down time.Duration
	if _, err := s.update(ctx, "boot", func(tx store.Tx) error {
		var err error
		down, err = s.plane.Boot(tx, s.now())
		return err
	}); err != nil {
		return fmt.Errorf("boot: %w", err)
	}
	s.log.Info().Dur("down", down).Msg("control plane booted; lease expiry held for at least one term")
	if w, ok := s.store.(Watcher); ok {
		go s.watch(ctx, w)
	}
	go s.census(ctx)
	t := time.NewTicker(s.cfg.SweepEvery)
	defer t.Stop()
	for {
		select {
		case <-ctx.Done():
			return nil
		case <-t.C:
			s.sweep(ctx)
		}
	}
}

// watch wakes polls for commits other replicas make. A break in the feed
// may hide changes, so every parked poll re-reads when the feed returns.
func (s *Server) watch(ctx context.Context, w Watcher) {
	for ctx.Err() == nil {
		ch, err := w.Watch(ctx)
		if err == nil {
			s.hub.wakeAll(s.now())
			for c := range ch {
				s.hub.publish(c, s.now())
			}
		}
		if ctx.Err() != nil {
			return
		}
		s.log.Warn().Err(err).Msg("store change feed broke; reconnecting")
		select {
		case <-ctx.Done():
		case <-time.After(time.Second):
		}
	}
}

// sweep heartbeats, then sweeps in batches until a batch comes back short.
func (s *Server) sweep(ctx context.Context) {
	var gap time.Duration
	if _, err := s.update(ctx, "heartbeat", func(tx store.Tx) error {
		var err error
		gap, err = s.plane.Heartbeat(tx, s.now())
		return err
	}); err != nil {
		s.log.Warn().Err(err).Msg("heartbeat failed")
		return
	}
	if gap > 0 {
		s.log.Warn().Dur("gap", gap).Msg("heartbeat resumed after a gap; lease expiry held for as long again")
	}
	for {
		var n int
		if _, err := s.update(ctx, "sweep", func(tx store.Tx) error {
			var err error
			n, err = s.plane.Sweep(tx, s.now())
			return err
		}); err != nil {
			s.log.Warn().Err(err).Msg("sweep failed")
			return
		}
		s.m.swept.Add(float64(n))
		if n > 0 {
			s.log.Info().Int("interfaces", n).Msg("swept leases, drains and retention")
		}
		if n < cp.SweepBatch {
			return
		}
	}
}

// census counts the pools for the metrics at once and every CensusEvery
// until ctx ends.
func (s *Server) census(ctx context.Context) {
	t := time.NewTicker(s.cfg.CensusEvery)
	defer t.Stop()
	for {
		var c cp.Census
		if err := s.view(ctx, "census", func(tx store.ReadTx) error {
			var err error
			c, err = s.plane.TakeCensus(tx, s.now())
			return err
		}); err == nil {
			s.m.observeCensus(c)
		} else if ctx.Err() == nil {
			s.log.Warn().Err(err).Msg("census failed")
		}
		s.limits.prune(s.now())
		select {
		case <-ctx.Done():
			return
		case <-t.C:
		}
	}
}

// update runs one transaction and wakes the polls its commit touches.
func (s *Server) update(ctx context.Context, op string, fn func(store.Tx) error) (store.Change, error) {
	start := time.Now()
	ch, err := s.store.Update(ctx, fn)
	s.m.observeTx(op, err, time.Since(start))
	if err == nil {
		s.hub.publish(ch, s.now())
	}
	return ch, err
}

func (s *Server) view(ctx context.Context, op string, fn func(store.ReadTx) error) error {
	start := time.Now()
	err := s.store.View(ctx, fn)
	s.m.observeTx(op, err, time.Since(start))
	return err
}

// route is one endpoint: who may call it, and what a call spends of a
// scoped principal's limits.
type route struct {
	pattern string
	auth    func(*http.Request) (principal, error)
	h       func(*http.Request, principal) (any, error)
	spends  spend
}

// spend is what a call takes from a scoped principal's limits.
type spend int

const (
	// aWrite takes a token from the write bucket and a call slot.
	aWrite spend = iota
	// aCall takes a call slot alone.
	aCall
	// nothing passes untouched, so a limit never costs a lease.
	nothing
)

// routes lists every endpoint. An admin route serves the operator and every
// admin token, and its handler bounds what the token may name; an operator
// route serves the operator alone.
func (s *Server) routes() []route {
	operator, admin, host, relay := s.authOperator, s.authAdmin, s.authHost, s.authRelay
	return []route{
		{"POST /v1/networks", operator, s.createNetwork, aWrite},
		{"GET /v1/networks", admin, s.listNetworks, aCall},
		{"GET /v1/networks/{net}", admin, s.getNetwork, aCall},
		{"DELETE /v1/networks/{net}", operator, s.deleteNetwork, aWrite},
		{"GET /v1/networks/{net}/quota", admin, s.getQuota, aCall},
		{"PUT /v1/networks/{net}/quota", operator, s.setQuota, aWrite},
		{"POST /v1/networks/{net}/services", admin, s.createService, aWrite},
		{"GET /v1/networks/{net}/services", admin, s.listServices, aCall},
		{"DELETE /v1/networks/{net}/services/{svc}", admin, s.deleteService, aWrite},
		{"POST /v1/networks/{net}/rules", admin, s.createRule, aWrite},
		{"GET /v1/networks/{net}/rules", admin, s.listRules, aCall},
		{"DELETE /v1/networks/{net}/rules/{rule}", admin, s.deleteRule, aWrite},
		{"GET /v1/networks/{net}/policy", admin, s.policy, aCall},
		{"GET /v1/networks/{net}/interfaces", admin, s.listInterfaces, aCall},
		{"POST /v1/interfaces/{id}/revoke", admin, s.revoke, aWrite},
		{"POST /v1/networks/{net}/devices", admin, s.createDevice, aWrite},
		{"POST /v1/hosts", admin, s.createHost, aWrite},
		{"GET /v1/hosts", admin, s.listHosts, aCall},
		{"PUT /v1/hosts/{host}/scope", admin, s.setHostScope, aWrite},
		{"DELETE /v1/hosts/{host}", admin, s.deleteHost, aWrite},
		{"POST /v1/relays", operator, s.createRelay, aWrite},
		{"GET /v1/relays", operator, s.listRelays, aCall},
		{"DELETE /v1/relays/{relay}", operator, s.deleteRelay, aWrite},
		{"POST /v1/admins", operator, s.createAdmin, aWrite},
		{"GET /v1/admins", operator, s.listAdmins, aCall},
		{"PUT /v1/admins/{admin}/scope", operator, s.setAdminScope, aWrite},
		{"DELETE /v1/admins/{admin}", operator, s.deleteAdmin, aWrite},

		{"POST /v1/agent/attach", host, s.attach, aWrite},
		{"POST /v1/agent/release", host, s.release, aWrite},
		{"POST /v1/agent/renew", host, s.renew, nothing},
		{"GET /v1/agent/state", host, s.hostPoll, aCall},

		{"GET /v1/relay/state", relay, s.relayPoll, aCall},
	}
}

// Handler returns the API's routes.
func (s *Server) Handler() http.Handler {
	mux := http.NewServeMux()
	for _, rt := range s.routes() {
		mux.HandleFunc(rt.pattern, func(w http.ResponseWriter, r *http.Request) {
			start := time.Now()
			p, err := rt.auth(r)
			var out any
			if err == nil && p.scoped && rt.spends != nothing {
				var done func()
				if done, err = s.limits.admit(p, rt.spends == aWrite, s.now()); err == nil {
					defer done()
				}
			}
			if err == nil {
				out, err = rt.h(r, p)
			}
			code := s.respond(w, r, out, err)
			s.m.requests.WithLabelValues(rt.pattern, strconv.Itoa(code)).Inc()
			s.m.latency.WithLabelValues(rt.pattern).Observe(time.Since(start).Seconds())
		})
	}
	return mux
}

// Serve serves the API on a listener until ctx ends.
func (s *Server) Serve(ctx context.Context, ln net.Listener) error {
	srv := &http.Server{
		Handler:           s.Handler(),
		ReadHeaderTimeout: 10 * time.Second,
		BaseContext:       func(net.Listener) context.Context { return ctx },
	}
	go func() {
		<-ctx.Done()
		shutdown, cancel := context.WithTimeout(context.Background(), 5*time.Second)
		defer cancel()
		srv.Shutdown(shutdown)
	}()
	s.log.Info().Str("addr", ln.Addr().String()).Msg("API listening")
	if err := srv.Serve(ln); !errors.Is(err, http.ErrServerClosed) {
		return err
	}
	return nil
}

// respond writes a result or an error and returns the status it sent.
func (s *Server) respond(w http.ResponseWriter, r *http.Request, out any, err error) int {
	w.Header().Set("Content-Type", "application/json")
	if err != nil {
		if l, ok := errors.AsType[*errLimited](err); ok {
			w.Header().Set("Retry-After", l.retryAfter())
		}
		code, body := errorBody(err)
		if code >= 500 {
			s.log.Error().Err(err).Str("route", r.Pattern).Msg("request failed")
		}
		w.WriteHeader(code)
		json.NewEncoder(w).Encode(body)
		return code
	}
	if out == nil {
		out = struct{}{}
	}
	json.NewEncoder(w).Encode(out)
	return http.StatusOK
}

func errorBody(err error) (int, *api.Error) {
	if l, ok := errors.AsType[*errLimited](err); ok {
		return http.StatusTooManyRequests, l.apiError()
	}
	var ae *api.Error
	switch {
	case errors.Is(err, errUnauthorized):
		return http.StatusUnauthorized, &api.Error{Code: api.CodeForbidden, Message: err.Error()}
	case errors.As(err, &ae):
	case errors.Is(err, store.ErrNotFound):
		ae = &api.Error{Code: api.CodeNotFound, Message: err.Error()}
	case errors.Is(err, store.ErrConflict):
		ae = &api.Error{Code: api.CodeConflict, Message: err.Error()}
	case errors.Is(err, context.Canceled), errors.Is(err, context.DeadlineExceeded):
		ae = &api.Error{Code: api.CodeUnavailable, Message: err.Error()}
	default:
		return http.StatusInternalServerError, &api.Error{Code: "internal", Message: "internal error"}
	}
	code := map[string]int{
		api.CodeNotFound:    http.StatusNotFound,
		api.CodeConflict:    http.StatusConflict,
		api.CodeInvalid:     http.StatusBadRequest,
		api.CodeExhausted:   http.StatusConflict,
		api.CodeForbidden:   http.StatusForbidden,
		api.CodeUnavailable: http.StatusServiceUnavailable,
	}[ae.Code]
	if code == 0 {
		code = http.StatusBadRequest
	}
	return code, ae
}

func decode[T any](r *http.Request) (T, error) {
	var v T
	dec := json.NewDecoder(http.MaxBytesReader(nil, r.Body, 1<<20))
	dec.DisallowUnknownFields()
	if err := dec.Decode(&v); err != nil {
		return v, &api.Error{Code: api.CodeInvalid, Message: "body: " + err.Error()}
	}
	return v, nil
}

func bearer(r *http.Request) string {
	h := r.Header.Get("Authorization")
	if t, ok := strings.CutPrefix(h, "Bearer "); ok {
		return t
	}
	return ""
}

// errUnauthorized answers a call whose bearer token names no principal
// allowed it. An agent treats it as permanent.
var errUnauthorized = errors.New("bad or missing bearer token")

// errCannotAuthenticate answers a call whose token the store could not look
// up. A caller retries it.
var errCannotAuthenticate = &api.Error{Code: api.CodeUnavailable, Message: "the control plane cannot check tokens now"}

// errOperatorOnly answers an admin token calling a route that takes the
// operator's.
var errOperatorOnly = &api.Error{Code: api.CodeForbidden, Message: "this call takes the operator's token"}

// authAdmin admits the operator's token and every admin token. What an
// admin token may name, its handler reads in the transaction that acts.
func (s *Server) authAdmin(r *http.Request) (principal, error) {
	if subtle.ConstantTimeCompare([]byte(bearer(r)), []byte(s.cfg.AdminToken)) == 1 {
		return principal{operator: true}, nil
	}
	p, err := s.lookup(r, func(tx store.ReadTx, h [32]byte) (principal, error) {
		a, err := tx.AdminByToken(h)
		return principal{admin: a.ID, scoped: true}, err
	})
	if err == nil && p.admin == "" {
		err = errUnauthorized
	}
	return p, err
}

// authOperator admits the operator's token alone.
func (s *Server) authOperator(r *http.Request) (principal, error) {
	p, err := s.authAdmin(r)
	if err == nil && !p.operator {
		err = errOperatorOnly
	}
	return p, err
}

// scopeOf reads what an admin may manage, inside the transaction that acts
// on it, so a re-scoped or deleted admin token holds on every replica at
// once and a network renamed between a check and its action cannot slip
// past.
func scopeOf(tx store.ReadTx, p principal) (store.Scope, error) {
	if p.operator {
		return cp.Global(), nil
	}
	a, err := tx.Admin(p.admin)
	if errors.Is(err, store.ErrNotFound) {
		return store.Scope{}, errUnauthorized
	}
	return a.Scope, err
}

// network resolves a call's network for p. One outside p's scope reads as
// absent.
func network(tx store.ReadTx, p principal, ref string) (store.Network, error) {
	by, err := scopeOf(tx, p)
	if err != nil {
		return store.Network{}, err
	}
	return cp.ResolveNetworkIn(tx, by, ref)
}

// lookup resolves a bearer token to its host or relay, and trusts what it
// finds for TokenTTL.
func (s *Server) lookup(r *http.Request, find func(store.ReadTx, [32]byte) (principal, error)) (principal, error) {
	t := bearer(r)
	if t == "" {
		return principal{}, errUnauthorized
	}
	hash := cp.HashToken(t)
	now := s.now()
	if c, ok := s.tokens.Load(hash); ok && now.Before(c.(cachedToken).until) {
		return c.(cachedToken).p, nil
	}
	var p principal
	err := s.view(r.Context(), "auth", func(tx store.ReadTx) error {
		var err error
		p, err = find(tx, hash)
		return err
	})
	switch {
	case errors.Is(err, store.ErrNotFound):
		s.tokens.Delete(hash)
		return principal{}, errUnauthorized
	case err != nil:
		return principal{}, fmt.Errorf("token lookup: %w: %w", errCannotAuthenticate, err)
	}
	s.tokens.Store(hash, cachedToken{p: p, until: now.Add(s.cfg.TokenTTL)})
	return p, nil
}

func (s *Server) authHost(r *http.Request) (principal, error) {
	p, err := s.lookup(r, func(tx store.ReadTx, h [32]byte) (principal, error) {
		host, err := tx.HostByToken(h)
		return principal{host: host.ID, scoped: !host.Scope.Global}, err
	})
	if err == nil && p.host == "" {
		err = errUnauthorized
	}
	return p, err
}

func (s *Server) authRelay(r *http.Request) (principal, error) {
	p, err := s.lookup(r, func(tx store.ReadTx, h [32]byte) (principal, error) {
		relay, err := tx.RelayByToken(h)
		return principal{relay: relay.ID}, err
	})
	if err == nil && p.relay == "" {
		err = errUnauthorized
	}
	return p, err
}

// lockedCache shares one compiled-network cache between requests.
type lockedCache struct {
	mu  sync.Mutex
	lru *cp.LRU
}

func (c *lockedCache) Get(n model.NetworkID, rev uint64) (cp.Compiled, bool) {
	c.mu.Lock()
	defer c.mu.Unlock()
	return c.lru.Get(n, rev)
}

func (c *lockedCache) Put(n model.NetworkID, rev uint64, v cp.Compiled) {
	c.mu.Lock()
	defer c.mu.Unlock()
	c.lru.Put(n, rev, v)
}
