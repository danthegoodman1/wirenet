// Package cpclient calls the control plane's HTTP API: the operator's
// resources, an agent's attach, release, renew and long poll, and a relay's
// long poll.
package cpclient

import (
	"bytes"
	"context"
	"crypto/tls"
	"crypto/x509"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"net"
	"net/http"
	"net/http/httptrace"
	"net/url"
	"os"
	"strconv"
	"strings"
	"time"

	"github.com/danthegoodman1/wirenet/internal/api"
	"github.com/danthegoodman1/wirenet/internal/model"
)

// Client is one principal's connection to the control plane.
type Client struct {
	base    string
	token   string
	http    *http.Client
	timeout time.Duration
	// dialTimeout bounds one TCP connect.
	dialTimeout time.Duration
}

// Options configure a client.
type Options struct {
	// CAFile, when set, is the only authority the client trusts.
	CAFile string
	// Timeout bounds a call that is not a long poll.
	Timeout time.Duration
	// DialTimeout bounds one TCP connect. A call whose connect gets no
	// answer dials again within its own timeout, since nothing was sent.
	DialTimeout time.Duration
	// Dial, when set, replaces the TCP dialer, for tests.
	Dial func(ctx context.Context, network, addr string) (net.Conn, error)
}

// New returns a client for the control plane at base, authenticating with
// token.
func New(base, token string, opts Options) (*Client, error) {
	if _, err := url.Parse(base); err != nil {
		return nil, err
	}
	if opts.DialTimeout == 0 {
		opts.DialTimeout = 3 * time.Second
	}
	dial := opts.Dial
	if dial == nil {
		dial = (&net.Dialer{KeepAlive: 30 * time.Second}).DialContext
	}
	tr := http.DefaultTransport.(*http.Transport).Clone()
	tr.MaxIdleConnsPerHost = 16
	tr.DialContext = func(ctx context.Context, network, addr string) (net.Conn, error) {
		ctx, cancel := context.WithTimeoutCause(ctx, opts.DialTimeout, errDialTimeout)
		defer cancel()
		c, err := dial(ctx, network, addr)
		if err != nil && errors.Is(context.Cause(ctx), errDialTimeout) {
			return nil, errDialTimeout
		}
		return c, err
	}
	if opts.CAFile != "" {
		pem, err := os.ReadFile(opts.CAFile)
		if err != nil {
			return nil, err
		}
		pool := x509.NewCertPool()
		if !pool.AppendCertsFromPEM(pem) {
			return nil, fmt.Errorf("%s holds no certificate", opts.CAFile)
		}
		tr.TLSClientConfig = &tls.Config{RootCAs: pool, MinVersion: tls.VersionTLS12}
	}
	if opts.Timeout == 0 {
		opts.Timeout = 10 * time.Second
	}
	return &Client{base: strings.TrimRight(base, "/"), token: token, http: &http.Client{Transport: tr}, timeout: opts.Timeout, dialTimeout: opts.DialTimeout}, nil
}

// ErrUnavailable wraps a failure to reach the control plane at all, as
// against an answer refusing the call.
var ErrUnavailable = errors.New("control plane unavailable")

// errDialTimeout is a TCP connect that got no answer in DialTimeout.
var errDialTimeout = errors.New("connect timed out")

// limited is an answer refusing a call over its principal's limit, before
// the call acted, with how long the server asked the caller to wait.
type limited struct {
	wait time.Duration
	err  *api.Error
}

func (l *limited) Error() string { return l.err.Error() }

// unavailable reports a limited call as one the caller retries, as it does
// a control plane briefly away.
func (l *limited) unavailable() error {
	return fmt.Errorf("%w: %w", ErrUnavailable, &api.Error{Code: api.CodeUnavailable, Message: "limited: " + l.err.Message})
}

// do makes a call, and makes it again after a limited answer's wait while
// the call's own timeout allows. A wait it cannot afford answers
// unavailable, which an agent retries as it does an outage.
func (c *Client) do(ctx context.Context, method, path string, in, out any, timeout time.Duration) error {
	ctx, cancel := context.WithTimeout(ctx, timeout)
	defer cancel()
	for {
		err := c.attempt(ctx, method, path, in, out)
		l, ok := errors.AsType[*limited](err)
		if !ok {
			return err
		}
		if dl, ok := ctx.Deadline(); ok && time.Until(dl) < l.wait {
			return l.unavailable()
		}
		select {
		case <-time.After(l.wait):
		case <-ctx.Done():
			return l.unavailable()
		}
	}
}

func (c *Client) attempt(ctx context.Context, method, path string, in, out any) error {
	var b []byte
	if in != nil {
		var err error
		if b, err = json.Marshal(in); err != nil {
			return err
		}
	}
	var resp *http.Response
	for unanswered := 0; ; unanswered++ {
		var body io.Reader
		if in != nil {
			body = bytes.NewReader(b)
		}
		var t attemptTrace
		req, err := http.NewRequestWithContext(httptrace.WithClientTrace(ctx, t.trace()), method, c.base+path, body)
		if err != nil {
			return err
		}
		req.Header.Set("Authorization", "Bearer "+c.token)
		if in != nil {
			req.Header.Set("Content-Type", "application/json")
		}
		resp, err = c.http.Do(req)
		if err == nil {
			break
		}
		// A connect that got no answer sent nothing, so another may.
		if errors.Is(err, errDialTimeout) && ctx.Err() == nil {
			continue
		}
		if unanswered > 0 {
			return fmt.Errorf("%w: %s %s: %v (%s, after %d connects unanswered in %v)", ErrUnavailable, method, path, err, t, unanswered, c.dialTimeout)
		}
		return fmt.Errorf("%w: %s %s: %v (%s)", ErrUnavailable, method, path, err, t)
	}
	defer resp.Body.Close()
	b, err := io.ReadAll(io.LimitReader(resp.Body, 64<<20))
	if err != nil {
		return fmt.Errorf("%w: %s %s: %v", ErrUnavailable, method, path, err)
	}
	if resp.StatusCode != http.StatusOK {
		var ae api.Error
		if json.Unmarshal(b, &ae) != nil || ae.Code == "" {
			ae = api.Error{Code: "http", Message: fmt.Sprintf("%s %s: %s", method, path, resp.Status)}
		}
		if resp.StatusCode == http.StatusTooManyRequests {
			wait := time.Second
			if secs, err := strconv.Atoi(resp.Header.Get("Retry-After")); err == nil && secs > 0 {
				wait = time.Duration(secs) * time.Second
			}
			return &limited{wait: wait, err: &ae}
		}
		// A failure on the server's side is worth retrying; the agent
		// tells retryable answers by their code.
		if ae.Code == api.CodeUnavailable || resp.StatusCode >= 500 {
			return fmt.Errorf("%w: %w", ErrUnavailable, &api.Error{Code: api.CodeUnavailable, Message: ae.Message})
		}
		return &ae
	}
	if out == nil {
		return nil
	}
	if err := json.Unmarshal(b, out); err != nil {
		return fmt.Errorf("%s %s: decoding answer: %w", method, path, err)
	}
	return nil
}

// attemptTrace records how far one request got, so a failure says whether
// it ever had a connection and whether the server could have seen it.
type attemptTrace struct {
	start      time.Time
	got, wrote time.Duration
	connected  bool
	reused     bool
	idle       time.Duration
	written    bool
}

func (t *attemptTrace) trace() *httptrace.ClientTrace {
	t.start = time.Now()
	return &httptrace.ClientTrace{
		GotConn: func(i httptrace.GotConnInfo) {
			t.connected, t.got, t.reused, t.idle = true, time.Since(t.start), i.Reused, i.IdleTime
		},
		WroteRequest: func(i httptrace.WroteRequestInfo) {
			if i.Err == nil {
				t.written, t.wrote = true, time.Since(t.start)
			}
		},
	}
}

func (t attemptTrace) String() string {
	if !t.connected {
		return "no connection"
	}
	conn := fmt.Sprintf("a new connection after %v", t.got.Round(time.Millisecond))
	if t.reused {
		conn = fmt.Sprintf("a connection idle %v", t.idle.Round(time.Millisecond))
	}
	if !t.written {
		return conn + ", request unwritten"
	}
	return fmt.Sprintf("%s, request written after %v", conn, t.wrote.Round(time.Millisecond))
}

func call[T any](c *Client, ctx context.Context, method, path string, in any) (T, error) {
	var out T
	err := c.do(ctx, method, path, in, &out, c.timeout)
	return out, err
}

func esc(s string) string { return url.PathEscape(s) }

// The admin API.

func (c *Client) CreateNetwork(ctx context.Context, req api.CreateNetwork) (api.Network, error) {
	return call[api.Network](c, ctx, "POST", "/v1/networks", req)
}

func (c *Client) Networks(ctx context.Context) ([]api.Network, error) {
	return call[[]api.Network](c, ctx, "GET", "/v1/networks", nil)
}

func (c *Client) Network(ctx context.Context, ref string) (api.Network, error) {
	return call[api.Network](c, ctx, "GET", "/v1/networks/"+esc(ref), nil)
}

func (c *Client) DeleteNetwork(ctx context.Context, ref string) error {
	return c.do(ctx, "DELETE", "/v1/networks/"+esc(ref), nil, nil, c.timeout)
}

// Quota reads a network's quota and what it holds against it.
func (c *Client) Quota(ctx context.Context, net string) (api.QuotaInfo, error) {
	return call[api.QuotaInfo](c, ctx, "GET", "/v1/networks/"+esc(net)+"/quota", nil)
}

// SetQuota replaces a network's quota.
func (c *Client) SetQuota(ctx context.Context, net string, q api.Quota) (api.Network, error) {
	return call[api.Network](c, ctx, "PUT", "/v1/networks/"+esc(net)+"/quota", q)
}

func (c *Client) CreateService(ctx context.Context, net string, req api.CreateService) (api.ServiceInfo, error) {
	return call[api.ServiceInfo](c, ctx, "POST", "/v1/networks/"+esc(net)+"/services", req)
}

func (c *Client) Services(ctx context.Context, net string) ([]api.ServiceInfo, error) {
	return call[[]api.ServiceInfo](c, ctx, "GET", "/v1/networks/"+esc(net)+"/services", nil)
}

func (c *Client) DeleteService(ctx context.Context, net, svc string) error {
	return c.do(ctx, "DELETE", "/v1/networks/"+esc(net)+"/services/"+esc(svc), nil, nil, c.timeout)
}

func (c *Client) CreateRule(ctx context.Context, net string, req api.CreateRule) (api.Rule, error) {
	return call[api.Rule](c, ctx, "POST", "/v1/networks/"+esc(net)+"/rules", req)
}

func (c *Client) Rules(ctx context.Context, net string) ([]api.Rule, error) {
	return call[[]api.Rule](c, ctx, "GET", "/v1/networks/"+esc(net)+"/rules", nil)
}

// Policy lists the flows a network's rules leave open.
func (c *Client) Policy(ctx context.Context, net string) ([]api.Grant, error) {
	return call[[]api.Grant](c, ctx, "GET", "/v1/networks/"+esc(net)+"/policy", nil)
}

func (c *Client) DeleteRule(ctx context.Context, net string, id model.RuleID) error {
	return c.do(ctx, "DELETE", "/v1/networks/"+esc(net)+"/rules/"+esc(string(id)), nil, nil, c.timeout)
}

func (c *Client) Interfaces(ctx context.Context, net string) ([]api.InterfaceInfo, error) {
	return call[[]api.InterfaceInfo](c, ctx, "GET", "/v1/networks/"+esc(net)+"/interfaces", nil)
}

// CreateDevice registers a development machine behind a gateway; the
// caller keeps the private key.
func (c *Client) CreateDevice(ctx context.Context, net string, req api.CreateDevice) (api.DeviceConfig, error) {
	return call[api.DeviceConfig](c, ctx, "POST", "/v1/networks/"+esc(net)+"/devices", req)
}

func (c *Client) Revoke(ctx context.Context, id model.InterfaceID) error {
	return c.do(ctx, "POST", "/v1/interfaces/"+esc(string(id))+"/revoke", nil, nil, c.timeout)
}

func (c *Client) CreateHost(ctx context.Context, req api.CreateHost) (api.Credentials, error) {
	return call[api.Credentials](c, ctx, "POST", "/v1/hosts", req)
}

// Hosts lists the hosts the caller manages.
func (c *Client) Hosts(ctx context.Context) ([]api.HostInfo, error) {
	return call[[]api.HostInfo](c, ctx, "GET", "/v1/hosts", nil)
}

// SetHostScope changes the networks a host may attach into, revoking its
// interfaces in the networks it loses.
func (c *Client) SetHostScope(ctx context.Context, ref string, sc api.Scope) (api.HostInfo, error) {
	return call[api.HostInfo](c, ctx, "PUT", "/v1/hosts/"+esc(ref)+"/scope", sc)
}

// DeleteHost revokes a host's interfaces and deletes the host, by name or
// identifier.
func (c *Client) DeleteHost(ctx context.Context, ref string) error {
	return c.do(ctx, "DELETE", "/v1/hosts/"+esc(ref), nil, nil, c.timeout)
}

func (c *Client) CreateRelay(ctx context.Context, req api.CreateRelay) (api.Credentials, error) {
	return call[api.Credentials](c, ctx, "POST", "/v1/relays", req)
}

func (c *Client) Relays(ctx context.Context) ([]api.RelayInfo, error) {
	return call[[]api.RelayInfo](c, ctx, "GET", "/v1/relays", nil)
}

// DeleteRelay deletes a relay no network names, by name or identifier.
func (c *Client) DeleteRelay(ctx context.Context, ref string) error {
	return c.do(ctx, "DELETE", "/v1/relays/"+esc(ref), nil, nil, c.timeout)
}

// CreateAdmin issues a token that manages the networks it names.
func (c *Client) CreateAdmin(ctx context.Context, req api.CreateAdmin) (api.Credentials, error) {
	return call[api.Credentials](c, ctx, "POST", "/v1/admins", req)
}

func (c *Client) Admins(ctx context.Context) ([]api.AdminInfo, error) {
	return call[[]api.AdminInfo](c, ctx, "GET", "/v1/admins", nil)
}

// SetAdminScope changes the networks an admin token manages.
func (c *Client) SetAdminScope(ctx context.Context, ref string, networks []string) (api.AdminInfo, error) {
	return call[api.AdminInfo](c, ctx, "PUT", "/v1/admins/"+esc(ref)+"/scope", api.Scope{Networks: networks})
}

// DeleteAdmin deletes an admin token, by name or identifier.
func (c *Client) DeleteAdmin(ctx context.Context, ref string) error {
	return c.do(ctx, "DELETE", "/v1/admins/"+esc(ref), nil, nil, c.timeout)
}

// An agent's API.

func (c *Client) Attach(ctx context.Context, req api.AttachRequest) (*api.AttachResponse, error) {
	resp, err := call[api.AttachResponse](c, ctx, "POST", "/v1/agent/attach", req)
	if err != nil {
		return nil, err
	}
	return &resp, nil
}

func (c *Client) Release(ctx context.Context, ids []model.InterfaceID) error {
	return c.do(ctx, "POST", "/v1/agent/release", api.ReleaseRequest{Interfaces: ids}, nil, c.timeout)
}

func (c *Client) Renew(ctx context.Context, ids []model.InterfaceID) (api.RenewResponse, error) {
	return call[api.RenewResponse](c, ctx, "POST", "/v1/agent/renew", api.RenewRequest{Interfaces: ids})
}

// HostState long-polls for desired state newer than since. wait bounds the
// whole call and should exceed the server's poll timeout.
func (c *Client) HostState(ctx context.Context, since uint64, wait time.Duration) (api.StateUpdate, error) {
	var u api.StateUpdate
	err := c.do(ctx, "GET", "/v1/agent/state?since="+strconv.FormatUint(since, 10), nil, &u, wait)
	return u, err
}

// A relay's API.

// RelayState long-polls for a port table newer than since.
func (c *Client) RelayState(ctx context.Context, since uint64, wait time.Duration) (api.RelayState, error) {
	var st api.RelayState
	err := c.do(ctx, "GET", "/v1/relay/state?since="+strconv.FormatUint(since, 10), nil, &st, wait)
	return st, err
}
