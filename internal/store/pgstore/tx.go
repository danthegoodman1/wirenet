package pgstore

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"math"
	"net/netip"
	"time"

	"github.com/jackc/pgx/v5"
	"github.com/jackc/pgx/v5/pgconn"

	"github.com/danthegoodman1/wirenet/internal/api"
	"github.com/danthegoodman1/wirenet/internal/model"
	"github.com/danthegoodman1/wirenet/internal/store"
	"github.com/danthegoodman1/wirenet/internal/store/pgstore/db"
)

// tx is one attempt at a transaction.
type tx struct {
	ctx context.Context
	q   *db.Queries
	// failed is the first statement error. Postgres aborts the transaction
	// at it, so nothing after it can commit.
	failed   error
	revision uint64
	change   store.Change
}

var _ store.Tx = (*tx)(nil)

// check turns a statement's error into the store's, and records a failure.
func (t *tx) check(err error) error {
	switch {
	case err == nil:
		return nil
	case errors.Is(err, pgx.ErrNoRows):
		return store.ErrNotFound
	}
	if t.failed == nil {
		t.failed = err
	}
	var pgErr *pgconn.PgError
	if errors.As(err, &pgErr) && pgErr.Code == uniqueViolation {
		return fmt.Errorf("%w: %w", store.ErrConflict, err)
	}
	return err
}

// one converts a single row, or returns the lookup's error.
func one[R, V any](t *tx, r R, err error, conv func(R) (V, error)) (V, error) {
	if err != nil {
		var zero V
		return zero, t.check(err)
	}
	return conv(r)
}

// all converts every row, or returns the query's error.
func all[R, V any](t *tx, rows []R, err error, conv func(R) (V, error)) ([]V, error) {
	if err != nil {
		return nil, t.check(err)
	}
	out := make([]V, len(rows))
	for i, r := range rows {
		if out[i], err = conv(r); err != nil {
			return nil, err
		}
	}
	return out, nil
}

// limit renders a list's bound as SQL's: NULL for none.
func limit(n int) *int32 {
	if n <= 0 {
		return nil
	}
	v := int32(min(n, math.MaxInt32))
	return &v
}

func (t *tx) Network(id model.NetworkID) (store.Network, error) {
	r, err := t.q.GetNetwork(t.ctx, string(id))
	return one(t, r, err, network)
}

func (t *tx) NetworkByName(name string) (store.Network, error) {
	r, err := t.q.GetNetworkByName(t.ctx, name)
	return one(t, r, err, network)
}

func (t *tx) Networks() ([]store.Network, error) {
	rows, err := t.q.ListNetworks(t.ctx)
	return all(t, rows, err, network)
}

func (t *tx) Service(id model.ServiceID) (store.Service, error) {
	r, err := t.q.GetService(t.ctx, string(id))
	return one(t, r, err, service)
}

func (t *tx) ServiceByName(net model.NetworkID, name string) (store.Service, error) {
	r, err := t.q.GetServiceByName(t.ctx, db.GetServiceByNameParams{Network: string(net), Name: name})
	return one(t, r, err, service)
}

func (t *tx) Services(net model.NetworkID) ([]store.Service, error) {
	rows, err := t.q.ListServices(t.ctx, string(net))
	return all(t, rows, err, service)
}

func (t *tx) Interface(id model.InterfaceID) (store.Interface, error) {
	r, err := t.q.GetInterface(t.ctx, string(id))
	return one(t, r, err, iface)
}

func (t *tx) Interfaces(net model.NetworkID) ([]store.Interface, error) {
	rows, err := t.q.ListInterfaces(t.ctx, string(net))
	return all(t, rows, err, iface)
}

func (t *tx) HostInterfaces(host model.HostID) ([]store.Interface, error) {
	rows, err := t.q.ListHostInterfaces(t.ctx, string(host))
	return all(t, rows, err, iface)
}

func (t *tx) Holder(svc model.ServiceID, member string) (store.Interface, error) {
	r, err := t.q.GetHolder(t.ctx, db.GetHolderParams{Service: string(svc), Member: member})
	return one(t, r, err, iface)
}

func (t *tx) Expired(before time.Time, n int) ([]store.Interface, error) {
	rows, err := t.q.ListExpired(t.ctx, db.ListExpiredParams{Before: before, Lim: limit(n)})
	return all(t, rows, err, iface)
}

func (t *tx) Undrained(before time.Time, n int) ([]store.Interface, error) {
	rows, err := t.q.ListUndrained(t.ctx, db.ListUndrainedParams{Before: before, Lim: limit(n)})
	return all(t, rows, err, iface)
}

func (t *tx) Ended(before time.Time, n int) ([]store.Interface, error) {
	rows, err := t.q.ListEnded(t.ctx, db.ListEndedParams{Before: before, Lim: limit(n)})
	return all(t, rows, err, iface)
}

func (t *tx) Rule(id model.RuleID) (store.Rule, error) {
	r, err := t.q.GetRule(t.ctx, string(id))
	return one(t, r, err, rule)
}

func (t *tx) Rules(net model.NetworkID) ([]store.Rule, error) {
	rows, err := t.q.ListRules(t.ctx, string(net))
	return all(t, rows, err, rule)
}

func (t *tx) Edges(net model.NetworkID) ([]store.Edge, error) {
	rows, err := t.q.ListEdges(t.ctx, string(net))
	return all(t, rows, err, edge)
}

func (t *tx) RelayEdges(relay model.RelayID) ([]store.Edge, error) {
	rows, err := t.q.ListRelayEdges(t.ctx, string(relay))
	return all(t, rows, err, edge)
}

func (t *tx) DormantEdges(before time.Time, n int) ([]store.Edge, error) {
	rows, err := t.q.ListDormantEdges(t.ctx, db.ListDormantEdgesParams{Before: before, Lim: limit(n)})
	return all(t, rows, err, edge)
}

func (t *tx) Host(id model.HostID) (store.Host, error) {
	r, err := t.q.GetHost(t.ctx, string(id))
	return one(t, r, err, host)
}

func (t *tx) HostByName(name string) (store.Host, error) {
	r, err := t.q.GetHostByName(t.ctx, name)
	return one(t, r, err, host)
}

func (t *tx) HostByToken(hash [32]byte) (store.Host, error) {
	r, err := t.q.GetHostByToken(t.ctx, hash[:])
	return one(t, r, err, host)
}

func (t *tx) Hosts() ([]store.Host, error) {
	rows, err := t.q.ListHosts(t.ctx)
	return all(t, rows, err, host)
}

func (t *tx) Admin(id model.AdminID) (store.Admin, error) {
	r, err := t.q.GetAdmin(t.ctx, string(id))
	return one(t, r, err, admin)
}

func (t *tx) AdminByName(name string) (store.Admin, error) {
	r, err := t.q.GetAdminByName(t.ctx, name)
	return one(t, r, err, admin)
}

func (t *tx) AdminByToken(hash [32]byte) (store.Admin, error) {
	r, err := t.q.GetAdminByToken(t.ctx, hash[:])
	return one(t, r, err, admin)
}

func (t *tx) Admins() ([]store.Admin, error) {
	rows, err := t.q.ListAdmins(t.ctx)
	return all(t, rows, err, admin)
}

func (t *tx) Relay(id model.RelayID) (store.Relay, error) {
	r, err := t.q.GetRelay(t.ctx, string(id))
	return one(t, r, err, relay)
}

func (t *tx) RelayByName(name string) (store.Relay, error) {
	r, err := t.q.GetRelayByName(t.ctx, name)
	return one(t, r, err, relay)
}

func (t *tx) RelayByToken(hash [32]byte) (store.Relay, error) {
	r, err := t.q.GetRelayByToken(t.ctx, hash[:])
	return one(t, r, err, relay)
}

func (t *tx) Relays() ([]store.Relay, error) {
	rows, err := t.q.ListRelays(t.ctx)
	return all(t, rows, err, relay)
}

func (t *tx) Released4(net model.NetworkID, before time.Time, n int) ([]store.Released4, error) {
	rows, err := t.q.ListReleased4(t.ctx, db.ListReleased4Params{Network: string(net), Before: before, Lim: limit(n)})
	return all(t, rows, err, func(r db.Released4) (store.Released4, error) {
		return store.Released4{Network: model.NetworkID(r.Network), Addr: r.Addr, At: r.At.UTC()}, nil
	})
}

func (t *tx) ReleasedPorts(relay model.RelayID, addr netip.Addr, before time.Time, n int) ([]store.ReleasedPort, error) {
	rows, err := t.q.ListReleasedPorts(t.ctx, db.ListReleasedPortsParams{Relay: string(relay), Addr: addr, Before: before, Lim: limit(n)})
	return all(t, rows, err, func(r db.ReleasedPort) (store.ReleasedPort, error) {
		return store.ReleasedPort{Relay: model.RelayID(r.Relay), Addr: r.Addr, Port: uint16(r.Port), At: r.At.UTC()}, nil
	})
}

func (t *tx) PortCursor(relay model.RelayID, addr netip.Addr) (uint16, error) {
	next, err := t.q.GetPortCursor(t.ctx, db.GetPortCursorParams{Relay: string(relay), Addr: addr})
	if errors.Is(err, pgx.ErrNoRows) {
		return 0, nil
	}
	return uint16(next), t.check(err)
}

func (t *tx) Meta(key string) (string, bool, error) {
	v, err := t.q.GetMeta(t.ctx, key)
	if errors.Is(err, pgx.ErrNoRows) {
		return "", false, nil
	}
	return v, err == nil, t.check(err)
}

func (t *tx) PutNetwork(n store.Network) error {
	relays, err := json.Marshal(n.Relays)
	if err != nil {
		return err
	}
	quota, err := json.Marshal(n.Quota)
	if err != nil {
		return err
	}
	written, err := t.q.PutNetwork(t.ctx, db.PutNetworkParams{
		ID: string(n.ID), Name: n.Name, Prefix6: n.Prefix6, Prefix4: n.Prefix4, Mtu: int64(n.MTU),
		Relays: relays, Next6: int64(n.Next6), Next4: int64(n.Next4), Revision: int64(n.Revision),
		Created: n.Created, Changed: n.Changed, Quota: quota,
	})
	return t.unique(written, err, "network", n.Name)
}

func (t *tx) DeleteNetwork(id model.NetworkID) error {
	return t.check(t.q.DeleteNetwork(t.ctx, string(id)))
}

func (t *tx) PutService(s store.Service) error {
	written, err := t.q.PutService(t.ctx, db.PutServiceParams{
		ID: string(s.ID), Network: string(s.Network), Name: s.Name, Ipv4: s.IPv4,
		Addr6: s.Addr6, Addr4: s.Addr4, Mode: string(s.Mode), Created: s.Created,
	})
	return t.unique(written, err, "service", s.Name)
}

func (t *tx) DeleteService(id model.ServiceID) error {
	return t.check(t.q.DeleteService(t.ctx, string(id)))
}

func (t *tx) PutInterface(i store.Interface) error {
	return t.check(t.q.PutInterface(t.ctx, db.PutInterfaceParams{
		ID: string(i.ID), Network: string(i.Network), Service: string(i.Service), Host: string(i.Host),
		Kind: string(i.Kind), Gateway: string(i.Gateway), PublicKey: i.PublicKey[:],
		Addr6: i.Addr6, Addr4: i.Addr4, ListenPort: int32(i.ListenPort), State: string(i.State),
		Expires: i.Expires, Created: i.Created, Ended: i.Ended, Drained: i.Drained, Member: i.Member,
	}))
}

func (t *tx) DeleteInterface(id model.InterfaceID) error {
	return t.check(t.q.DeleteInterface(t.ctx, string(id)))
}

func (t *tx) PutRule(r store.Rule) error {
	return t.check(t.q.PutRule(t.ctx, db.PutRuleParams{
		ID: string(r.ID), Network: string(r.Network), FromService: string(r.From), ToService: string(r.To),
		Proto: string(r.Proto), PortLo: int32(r.Ports.Lo), PortHi: int32(r.Ports.Hi), Created: r.Created,
		Deny: r.Deny,
	}))
}

func (t *tx) DeleteRule(id model.RuleID) error {
	return t.check(t.q.DeleteRule(t.ctx, string(id)))
}

func (t *tx) PutEdge(e store.Edge) error {
	ports, err := json.Marshal(e.Ports)
	if err != nil {
		return err
	}
	var dormant *time.Time
	if !e.Dormant.IsZero() {
		dormant = &e.Dormant
	}
	return t.check(t.q.PutEdge(t.ctx, db.PutEdgeParams{
		Network: string(e.Network), A: string(e.A), B: string(e.B),
		SecretAb: e.SecretAB[:], SecretBa: e.SecretBA[:], Ports: ports, Created: e.Created, Dormant: dormant,
	}))
}

func (t *tx) DeleteEdge(net model.NetworkID, a, b model.InterfaceID) error {
	return t.check(t.q.DeleteEdge(t.ctx, db.DeleteEdgeParams{Network: string(net), A: string(a), B: string(b)}))
}

func (t *tx) PutHost(h store.Host) error {
	endpoint, err := h.Endpoint.MarshalText()
	if err != nil {
		return err
	}
	networks, err := scopeNetworks(h.Scope)
	if err != nil {
		return err
	}
	written, err := t.q.PutHost(t.ctx, db.PutHostParams{
		ID: string(h.ID), Name: h.Name, TokenHash: h.TokenHash[:], Endpoint: string(endpoint),
		Revision: int64(h.Revision), Created: h.Created, Global: h.Scope.Global, Networks: networks,
	})
	return t.unique(written, err, "host", h.Name)
}

func (t *tx) PutAdmin(a store.Admin) error {
	networks, err := scopeNetworks(a.Scope)
	if err != nil {
		return err
	}
	written, err := t.q.PutAdmin(t.ctx, db.PutAdminParams{
		ID: string(a.ID), Name: a.Name, TokenHash: a.TokenHash[:], Global: a.Scope.Global,
		Networks: networks, Created: a.Created,
	})
	return t.unique(written, err, "admin", a.Name)
}

func (t *tx) DeleteAdmin(id model.AdminID) error {
	return t.check(t.q.DeleteAdmin(t.ctx, string(id)))
}

// scopeNetworks renders a scope's networks as a JSON array, never null.
func scopeNetworks(s store.Scope) ([]byte, error) {
	if s.Networks == nil {
		return []byte("[]"), nil
	}
	return json.Marshal(s.Networks)
}

// scope reads a scope back, keeping a list that names nothing nil.
func scope(global bool, networks []byte) (store.Scope, error) {
	s := store.Scope{Global: global}
	if err := json.Unmarshal(networks, &s.Networks); err != nil {
		return store.Scope{}, err
	}
	if len(s.Networks) == 0 {
		s.Networks = nil
	}
	return s, nil
}

func (t *tx) DeleteHost(id model.HostID) error {
	return t.check(t.q.DeleteHost(t.ctx, string(id)))
}

func (t *tx) PutRelay(r store.Relay) error {
	addresses, err := json.Marshal(r.Addresses)
	if err != nil {
		return err
	}
	written, err := t.q.PutRelay(t.ctx, db.PutRelayParams{
		ID: string(r.ID), Name: r.Name, TokenHash: r.TokenHash[:], Addresses: addresses,
		PortLo: int32(r.PortLo), PortHi: int32(r.PortHi), ProbePort: int32(r.ProbePort),
		Revision: int64(r.Revision), Created: r.Created,
	})
	return t.unique(written, err, "relay", r.Name)
}

func (t *tx) DeleteRelay(id model.RelayID) error {
	if err := t.check(t.q.DeleteRelay(t.ctx, string(id))); err != nil {
		return err
	}
	if err := t.check(t.q.DeleteRelayPorts(t.ctx, string(id))); err != nil {
		return err
	}
	return t.check(t.q.DeleteRelayCursors(t.ctx, string(id)))
}

// unique reports a put that wrote nothing because another record holds its
// name.
func (t *tx) unique(written int64, err error, kind, name string) error {
	if err != nil {
		return t.check(err)
	}
	if written == 0 {
		return fmt.Errorf("%w: %s %q", store.ErrConflict, kind, name)
	}
	return nil
}

func (t *tx) PutReleased4(r store.Released4) error {
	return t.check(t.q.PutReleased4(t.ctx, db.PutReleased4Params{Network: string(r.Network), Addr: r.Addr, At: r.At}))
}

func (t *tx) DeleteReleased4(net model.NetworkID, addr netip.Addr) error {
	return t.check(t.q.DeleteReleased4(t.ctx, db.DeleteReleased4Params{Network: string(net), Addr: addr}))
}

func (t *tx) PutReleasedPort(p store.ReleasedPort) error {
	return t.check(t.q.PutReleasedPort(t.ctx, db.PutReleasedPortParams{
		Relay: string(p.Relay), Addr: p.Addr, Port: int32(p.Port), At: p.At,
	}))
}

func (t *tx) DeleteReleasedPort(relay model.RelayID, addr netip.Addr, port uint16) error {
	return t.check(t.q.DeleteReleasedPort(t.ctx, db.DeleteReleasedPortParams{Relay: string(relay), Addr: addr, Port: int32(port)}))
}

func (t *tx) SetPortCursor(relay model.RelayID, addr netip.Addr, next uint16) error {
	return t.check(t.q.SetPortCursor(t.ctx, db.SetPortCursorParams{Relay: string(relay), Addr: addr, Next: int32(next)}))
}

func (t *tx) SetMeta(key, value string) error {
	return t.check(t.q.SetMeta(t.ctx, db.SetMetaParams{Key: key, Value: value}))
}

// Bump takes the next revision from the revision row and keeps it for the
// rest of the transaction. The row stays locked until the transaction ends,
// and a concurrent bumper fails to serialize and runs again after it.
func (t *tx) Bump() (uint64, error) {
	if t.revision == 0 {
		seq, err := t.q.Bump(t.ctx)
		if err != nil {
			return 0, t.check(err)
		}
		t.revision = uint64(seq)
	}
	return t.revision, nil
}

func (t *tx) Touch(c store.Change) { t.change.Merge(c) }

// notify announces ch to every replica's Watch. Postgres delivers the
// notifications when the transaction commits, and drops them if it aborts.
func (t *tx) notify(ch store.Change) error {
	if ch.Empty() && ch.Revision == 0 {
		return nil
	}
	ps, err := payloads(ch)
	if err != nil {
		return err
	}
	for _, p := range ps {
		if err := t.q.Notify(t.ctx, db.NotifyParams{Channel: Channel, Payload: p}); err != nil {
			return t.check(err)
		}
	}
	return nil
}

func network(r db.Network) (store.Network, error) {
	n := store.Network{
		ID: model.NetworkID(r.ID), Name: r.Name, Prefix6: r.Prefix6, Prefix4: r.Prefix4, MTU: int(r.Mtu),
		Next6: uint64(r.Next6), Next4: uint64(r.Next4), Revision: uint64(r.Revision), Created: r.Created.UTC(),
		Changed: r.Changed.UTC(),
	}
	if err := json.Unmarshal(r.Relays, &n.Relays); err != nil {
		return store.Network{}, fmt.Errorf("network %s relays: %w", r.ID, err)
	}
	if err := json.Unmarshal(r.Quota, &n.Quota); err != nil {
		return store.Network{}, fmt.Errorf("network %s quota: %w", r.ID, err)
	}
	return n, nil
}

func service(r db.Service) (store.Service, error) {
	return store.Service{
		ID: model.ServiceID(r.ID), Network: model.NetworkID(r.Network), Name: r.Name, IPv4: r.Ipv4,
		Addr6: r.Addr6, Addr4: r.Addr4, Mode: api.Mode(r.Mode), Created: r.Created.UTC(),
	}, nil
}

func iface(r db.Interface) (store.Interface, error) {
	key, err := bytes32(r.PublicKey)
	if err != nil {
		return store.Interface{}, fmt.Errorf("interface %s public key: %w", r.ID, err)
	}
	return store.Interface{
		ID: model.InterfaceID(r.ID), Network: model.NetworkID(r.Network), Service: model.ServiceID(r.Service),
		Host: model.HostID(r.Host), Kind: api.Kind(r.Kind), Gateway: model.InterfaceID(r.Gateway),
		PublicKey: model.Key(key), Addr6: r.Addr6, Addr4: r.Addr4, ListenPort: uint16(r.ListenPort),
		State: api.LeaseState(r.State), Expires: r.Expires.UTC(), Created: r.Created.UTC(),
		Ended: r.Ended.UTC(), Drained: r.Drained, Member: r.Member,
	}, nil
}

func rule(r db.Rule) (store.Rule, error) {
	return store.Rule{
		ID: model.RuleID(r.ID), Network: model.NetworkID(r.Network), From: model.ServiceID(r.FromService),
		To: model.ServiceID(r.ToService), Proto: model.Proto(r.Proto),
		Ports: model.PortRange{Lo: uint16(r.PortLo), Hi: uint16(r.PortHi)}, Created: r.Created.UTC(),
		Deny: r.Deny,
	}, nil
}

func edge(r db.Edge) (store.Edge, error) {
	ab, err := bytes32(r.SecretAb)
	if err != nil {
		return store.Edge{}, fmt.Errorf("edge %s %s-%s secret: %w", r.Network, r.A, r.B, err)
	}
	ba, err := bytes32(r.SecretBa)
	if err != nil {
		return store.Edge{}, fmt.Errorf("edge %s %s-%s secret: %w", r.Network, r.A, r.B, err)
	}
	e := store.Edge{
		Network: model.NetworkID(r.Network), A: model.InterfaceID(r.A), B: model.InterfaceID(r.B),
		SecretAB: model.Secret(ab), SecretBA: model.Secret(ba), Created: r.Created.UTC(),
	}
	if r.Dormant != nil {
		e.Dormant = r.Dormant.UTC()
	}
	if err := json.Unmarshal(r.Ports, &e.Ports); err != nil {
		return store.Edge{}, fmt.Errorf("edge %s %s-%s ports: %w", r.Network, r.A, r.B, err)
	}
	return e, nil
}

func host(r db.Host) (store.Host, error) {
	hash, err := bytes32(r.TokenHash)
	if err != nil {
		return store.Host{}, fmt.Errorf("host %s token hash: %w", r.ID, err)
	}
	h := store.Host{
		ID: model.HostID(r.ID), Name: r.Name, TokenHash: hash, Revision: uint64(r.Revision), Created: r.Created.UTC(),
	}
	if err := h.Endpoint.UnmarshalText([]byte(r.Endpoint)); err != nil {
		return store.Host{}, fmt.Errorf("host %s endpoint: %w", r.ID, err)
	}
	if h.Scope, err = scope(r.Global, r.Networks); err != nil {
		return store.Host{}, fmt.Errorf("host %s scope: %w", r.ID, err)
	}
	return h, nil
}

func admin(r db.Admin) (store.Admin, error) {
	hash, err := bytes32(r.TokenHash)
	if err != nil {
		return store.Admin{}, fmt.Errorf("admin %s token hash: %w", r.ID, err)
	}
	sc, err := scope(r.Global, r.Networks)
	if err != nil {
		return store.Admin{}, fmt.Errorf("admin %s scope: %w", r.ID, err)
	}
	return store.Admin{ID: model.AdminID(r.ID), Name: r.Name, TokenHash: hash, Scope: sc, Created: r.Created.UTC()}, nil
}

func relay(r db.Relay) (store.Relay, error) {
	hash, err := bytes32(r.TokenHash)
	if err != nil {
		return store.Relay{}, fmt.Errorf("relay %s token hash: %w", r.ID, err)
	}
	out := store.Relay{
		ID: model.RelayID(r.ID), Name: r.Name, TokenHash: hash, PortLo: uint16(r.PortLo),
		PortHi: uint16(r.PortHi), ProbePort: uint16(r.ProbePort), Revision: uint64(r.Revision),
		Created: r.Created.UTC(),
	}
	if err := json.Unmarshal(r.Addresses, &out.Addresses); err != nil {
		return store.Relay{}, fmt.Errorf("relay %s addresses: %w", r.ID, err)
	}
	return out, nil
}

func bytes32(b []byte) ([32]byte, error) {
	if len(b) != 32 {
		return [32]byte{}, fmt.Errorf("%d bytes, want 32", len(b))
	}
	return [32]byte(b), nil
}
