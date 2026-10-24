//wirenet:deterministic

package cp

import (
	"errors"
	"maps"
	"slices"
	"strings"
	"time"

	"github.com/danthegoodman1/wirenet/internal/api"
	"github.com/danthegoodman1/wirenet/internal/compile"
	"github.com/danthegoodman1/wirenet/internal/model"
	"github.com/danthegoodman1/wirenet/internal/store"
)

// Global returns the scope of the operator's own token and of a global
// host.
func Global() store.Scope { return store.Scope{Global: true} }

// ResolveNetworkIn finds a network a scope admits. One outside it reads as
// absent, so a scoped principal learns nothing of another tenant's names.
func ResolveNetworkIn(tx store.ReadTx, sc store.Scope, ref string) (store.Network, error) {
	n, err := ResolveNetwork(tx, ref)
	if err == nil && !sc.Admits(n.ID) {
		return store.Network{}, notFound(store.ErrNotFound, "network "+ref)
	}
	return n, err
}

// ResolveScope finds the networks refs name, each one within admits, and
// returns them as a scope listing each identifier once, sorted.
func ResolveScope(tx store.ReadTx, within store.Scope, refs []string) (store.Scope, error) {
	var sc store.Scope
	for _, ref := range refs {
		n, err := ResolveNetworkIn(tx, within, ref)
		if err != nil {
			return store.Scope{}, err
		}
		sc.Networks = append(sc.Networks, n.ID)
	}
	slices.Sort(sc.Networks)
	sc.Networks = slices.Compact(sc.Networks)
	return sc, nil
}

// Manages reports whether a principal of scope by may manage a host of
// scope sc: by admits every network sc does, and sc admits at least one, so
// a host that admits nothing answers to the global admin alone.
func Manages(by, sc store.Scope) bool {
	return by.Global || !sc.Global && len(sc.Networks) > 0 && sc.Within(by)
}

// ResolveHostIn finds a host a principal of scope by manages. One it does
// not manage reads as absent.
func ResolveHostIn(tx store.ReadTx, by store.Scope, ref string) (store.Host, error) {
	h, err := ResolveHost(tx, ref)
	if err == nil && !Manages(by, h.Scope) {
		return store.Host{}, notFound(store.ErrNotFound, "host "+ref)
	}
	return h, err
}

// HostsIn lists the hosts a principal of scope by manages.
func HostsIn(tx store.ReadTx, by store.Scope) ([]store.Host, error) {
	hosts, err := tx.Hosts()
	return slices.DeleteFunc(hosts, func(h store.Host) bool { return !Manages(by, h.Scope) }), err
}

// hostScope resolves the scope a principal of scope by gives a host. A
// global host takes a global principal; a scoped one names at least one
// network, each within by.
func hostScope(tx store.ReadTx, by store.Scope, req api.Scope) (store.Scope, error) {
	if req.Global {
		if !by.Global {
			return store.Scope{}, apiErr(api.CodeForbidden, "only the global admin gives a host every network")
		}
		if len(req.Networks) > 0 {
			return store.Scope{}, apiErr(api.CodeInvalid, "a global scope lists no networks")
		}
		return Global(), nil
	}
	if len(req.Networks) == 0 && !by.Global {
		return store.Scope{}, apiErr(api.CodeForbidden, "a scoped admin's hosts name at least one of its networks")
	}
	return ResolveScope(tx, by, req.Networks)
}

// SetHostScope changes the networks a host may attach into, and revokes
// its interfaces in every network the change removes, so no host holds an
// interface its scope does not admit. It returns the interfaces it
// revoked.
func (p *Plane) SetHostScope(tx store.Tx, now time.Time, by store.Scope, ref string, req api.Scope) (store.Host, []model.InterfaceID, error) {
	h, err := ResolveHostIn(tx, by, ref)
	if err != nil {
		return store.Host{}, nil, err
	}
	sc, err := hostScope(tx, by, req)
	if err != nil {
		return store.Host{}, nil, err
	}
	ifaces, err := tx.HostInterfaces(h.ID)
	if err != nil {
		return store.Host{}, nil, err
	}
	var revoked []model.InterfaceID
	for _, i := range ifaces {
		// A draining interface is still on its peers, so it goes too. A
		// gateway's revocation ends the development machines behind it.
		if compile.Connected(i) && compile.Built(i) && !sc.Admits(i.Network) {
			if err := p.Revoke(tx, now, i.ID); err != nil {
				return store.Host{}, nil, err
			}
			revoked = append(revoked, i.ID)
		}
	}
	// A network the scope gains returns to the host's poll at a revision
	// its agent may have passed while the network was out of scope, and
	// a poll carries only the networks newer than what the agent holds.
	regained := map[model.NetworkID]bool{}
	for _, i := range ifaces {
		if compile.Built(i) && sc.Admits(i.Network) && !h.Scope.Admits(i.Network) {
			regained[i.Network] = true
		}
	}
	for _, id := range slices.Sorted(maps.Keys(regained)) {
		n, err := tx.Network(id)
		if err != nil {
			return store.Host{}, nil, err
		}
		if err := bump(tx, now, &n); err != nil {
			return store.Host{}, nil, err
		}
	}
	// A revocation moves the host's revision, so write over what it wrote.
	if h, err = tx.Host(h.ID); err != nil {
		return store.Host{}, nil, err
	}
	h.Scope = sc
	if err := tx.PutHost(h); err != nil {
		return store.Host{}, nil, err
	}
	// The host's poll answers from its new scope at once: its generation
	// passes every revision it holds of a network the scope lost, so its
	// agent drops that network even when nothing in it was revoked.
	if err := bumpHosts(tx, []model.HostID{h.ID}); err != nil {
		return store.Host{}, nil, err
	}
	h, err = tx.Host(h.ID)
	return h, revoked, err
}

// dropFromScopes takes a deleted network out of every host's and admin's
// scope, so none names an identifier nothing can name again. A list it
// empties admits nothing.
func dropFromScopes(tx store.Tx, id model.NetworkID) error {
	hosts, err := tx.Hosts()
	if err != nil {
		return err
	}
	for _, h := range hosts {
		var held bool
		if h.Scope, held = h.Scope.Without(id); held {
			if err := tx.PutHost(h); err != nil {
				return err
			}
		}
	}
	admins, err := tx.Admins()
	if err != nil {
		return err
	}
	for _, a := range admins {
		var held bool
		if a.Scope, held = a.Scope.Without(id); held {
			if err := tx.PutAdmin(a); err != nil {
				return err
			}
		}
	}
	return nil
}

// RevokeIn revokes an interface of a network the scope by admits. One
// outside it reads as absent.
func (p *Plane) RevokeIn(tx store.Tx, now time.Time, by store.Scope, id model.InterfaceID) error {
	if !by.Global {
		i, err := tx.Interface(id)
		if err == nil && !by.Admits(i.Network) {
			err = store.ErrNotFound
		}
		if err != nil {
			return notFound(err, "interface "+string(id))
		}
	}
	return p.Revoke(tx, now, id)
}

// ResolveAdmin finds an admin by name, or failing that by identifier.
func ResolveAdmin(tx store.ReadTx, ref string) (store.Admin, error) {
	a, err := tx.AdminByName(ref)
	if errors.Is(err, store.ErrNotFound) && strings.HasPrefix(ref, model.AdminPrefix) {
		a, err = tx.Admin(model.AdminID(ref))
	}
	return a, notFound(err, "admin "+ref)
}

// adminScope resolves an admin token's networks, of which it needs one.
func adminScope(tx store.ReadTx, refs []string) (store.Scope, error) {
	if len(refs) == 0 {
		return store.Scope{}, apiErr(api.CodeInvalid, "an admin token manages at least one network")
	}
	return ResolveScope(tx, Global(), refs)
}

// CreateAdmin issues a token that manages the networks the request names,
// and returns it.
func (p *Plane) CreateAdmin(tx store.Tx, now time.Time, req api.CreateAdmin) (store.Admin, string, error) {
	if !ValidName(req.Name) {
		return store.Admin{}, "", apiErr(api.CodeInvalid, "admin name %q is not a DNS label", req.Name)
	}
	sc, err := adminScope(tx, req.Networks)
	if err != nil {
		return store.Admin{}, "", err
	}
	id, err := p.id(model.AdminPrefix)
	if err != nil {
		return store.Admin{}, "", err
	}
	token, hash, err := p.token()
	if err != nil {
		return store.Admin{}, "", err
	}
	a := store.Admin{ID: model.AdminID(id), Name: req.Name, TokenHash: hash, Scope: sc, Created: now}
	if err := tx.PutAdmin(a); err != nil {
		return store.Admin{}, "", conflict(err, "admin "+req.Name)
	}
	return a, token, nil
}

// SetAdminScope changes the networks an admin token manages.
func (p *Plane) SetAdminScope(tx store.Tx, ref string, networks []string) (store.Admin, error) {
	a, err := ResolveAdmin(tx, ref)
	if err != nil {
		return store.Admin{}, err
	}
	if a.Scope, err = adminScope(tx, networks); err != nil {
		return store.Admin{}, err
	}
	return a, tx.PutAdmin(a)
}

// DeleteAdmin removes an admin token.
func (p *Plane) DeleteAdmin(tx store.Tx, ref string) (store.Admin, error) {
	a, err := ResolveAdmin(tx, ref)
	if err != nil {
		return store.Admin{}, err
	}
	return a, tx.DeleteAdmin(a.ID)
}

// validQuota checks that no bound is negative.
func validQuota(q api.Quota) error {
	if q.Interfaces < 0 || q.Services < 0 || q.Rules < 0 || q.Edges < 0 {
		return apiErr(api.CodeInvalid, "a quota's bounds are zero, for none, or positive")
	}
	return nil
}

// mergeQuota fills each bound q leaves unset from def.
func mergeQuota(q, def api.Quota) api.Quota {
	pick := func(v, d int) int {
		if v != 0 {
			return v
		}
		return d
	}
	return api.Quota{
		Interfaces: pick(q.Interfaces, def.Interfaces), Services: pick(q.Services, def.Services),
		Rules: pick(q.Rules, def.Rules), Edges: pick(q.Edges, def.Edges),
	}
}

// SetQuota replaces what a network may hold, an unset bound leaving it
// unbounded. A bound below what the network holds stops it growing and
// removes nothing.
func (p *Plane) SetQuota(tx store.Tx, netRef string, q api.Quota) (store.Network, error) {
	n, err := ResolveNetwork(tx, netRef)
	if err != nil {
		return store.Network{}, err
	}
	if err := validQuota(q); err != nil {
		return store.Network{}, err
	}
	// Agents compile nothing from a quota, so the revision stays.
	n.Quota = q
	return n, tx.PutNetwork(n)
}

// Usage counts what a network holds against its quota.
func Usage(tx store.ReadTx, n store.Network) (api.Quota, error) {
	ifaces, err := tx.Interfaces(n.ID)
	if err != nil {
		return api.Quota{}, err
	}
	svcs, err := tx.Services(n.ID)
	if err != nil {
		return api.Quota{}, err
	}
	rules, err := tx.Rules(n.ID)
	if err != nil {
		return api.Quota{}, err
	}
	edges, err := tx.Edges(n.ID)
	if err != nil {
		return api.Quota{}, err
	}
	return api.Quota{Interfaces: live(ifaces), Services: len(svcs), Rules: len(rules), Edges: len(edges)}, nil
}

func live(ifaces []store.Interface) int {
	n := 0
	for _, i := range ifaces {
		if i.State == api.Live {
			n++
		}
	}
	return n
}

// overQuota refuses a change that takes a count from before to after past
// its bound. A count already over a lowered bound may stay or fall.
func overQuota(what string, bound, before, after int) error {
	if bound > 0 && after > bound && after > before {
		return apiErr(api.CodeExhausted, "the network would hold %d %s, over its quota of %d", after, what, bound)
	}
	return nil
}
