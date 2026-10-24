package cpserver

import (
	"errors"
	"math"
	"strconv"
	"sync"
	"time"

	"github.com/danthegoodman1/wirenet/internal/api"
)

// Limits bound each scoped principal's calls on one replica, so a tenant's
// host or admin token cannot take the control plane's writes, which every
// network shares, from the rest of the fleet. Global principals are exempt.
// Each replica keeps its own count, so a principal spread over N replicas
// gets up to N times the limit.
type Limits struct {
	// Rate is how many calls that write a principal may make a second,
	// sustained; zero leaves writes unbounded. Renewals spend nothing of
	// any limit, so a limit never costs a lease.
	Rate float64
	// Burst is how many writes a principal may make at once.
	Burst int
	// InFlight bounds a principal's calls running at once, long polls
	// included; zero leaves them unbounded.
	InFlight int
}

// DefaultLimits returns the production limits.
func DefaultLimits() Limits {
	return Limits{Rate: 10, Burst: 50, InFlight: 16}
}

func (l Limits) validate() error {
	if l.Rate < 0 || l.Burst < 0 || l.InFlight < 0 || l.Rate > 0 && l.Burst < 1 {
		return errors.New("limits must not be negative, and a rate needs a burst of at least one")
	}
	return nil
}

// limiter counts each scoped principal's calls. prune drops the entries
// that hold nothing, so the map holds only principals with calls running
// or tokens spent.
type limiter struct {
	cfg Limits
	mu  sync.Mutex
	by  map[principal]*bucket
}

type bucket struct {
	tokens   float64
	at       time.Time
	inFlight int
}

func newLimiter(cfg Limits) *limiter {
	return &limiter{cfg: cfg, by: map[principal]*bucket{}}
}

// errLimited refuses a call over its principal's limit, before it acts.
type errLimited struct {
	retry time.Duration
	why   string
}

func (e *errLimited) Error() string { return "limited: " + e.why }

// retryAfter renders the wait in whole seconds, at least one.
func (e *errLimited) retryAfter() string {
	return strconv.Itoa(max(1, int(math.Ceil(e.retry.Seconds()))))
}

func (e *errLimited) apiError() *api.Error {
	return &api.Error{Code: api.CodeLimited, Message: e.why}
}

// admit counts a call against p at now, and returns what ends it.
func (l *limiter) admit(p principal, writes bool, now time.Time) (func(), error) {
	l.mu.Lock()
	defer l.mu.Unlock()
	b, ok := l.by[p]
	if !ok {
		b = &bucket{tokens: float64(l.cfg.Burst), at: now}
		l.by[p] = b
	}
	if l.cfg.InFlight > 0 && b.inFlight >= l.cfg.InFlight {
		return nil, &errLimited{retry: time.Second, why: strconv.Itoa(l.cfg.InFlight) + " calls already running"}
	}
	if writes && l.cfg.Rate > 0 {
		// A call clocked before one that took the lock first refills
		// nothing, so the bucket's time never runs backward.
		if d := now.Sub(b.at); d > 0 {
			b.tokens = min(float64(l.cfg.Burst), b.tokens+d.Seconds()*l.cfg.Rate)
			b.at = now
		}
		if b.tokens < 1 {
			wait := time.Duration((1 - b.tokens) / l.cfg.Rate * float64(time.Second))
			return nil, &errLimited{retry: wait, why: "over " + strconv.FormatFloat(l.cfg.Rate, 'f', -1, 64) + " writes a second"}
		}
		b.tokens--
	}
	b.inFlight++
	return func() {
		l.mu.Lock()
		b.inFlight--
		l.mu.Unlock()
	}, nil
}

// prune drops the buckets with no call running that would have refilled
// by now, whose principals start afresh at no cost to them.
func (l *limiter) prune(now time.Time) {
	l.mu.Lock()
	defer l.mu.Unlock()
	for p, b := range l.by {
		full := l.cfg.Rate == 0 || b.tokens+now.Sub(b.at).Seconds()*l.cfg.Rate >= float64(l.cfg.Burst)
		if b.inFlight == 0 && full {
			delete(l.by, p)
		}
	}
}
