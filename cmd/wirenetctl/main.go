// Command wirenetctl drives the control plane's admin API and a host
// agent's local API.
//
//	wirenetctl network create NAME [--prefix6 P] [--prefix4 P] [--mtu N] [--relays R1,R2] [QUOTA]
//	wirenetctl network list | get NET | delete NET
//	wirenetctl quota show NET | set NET [QUOTA]
//	wirenetctl service create NET NAME [--ipv4] [--mode flip|cutover]
//	wirenetctl service list NET | delete NET SVC
//	wirenetctl rule create NET FROM TO [--deny] [--proto tcp|udp|any] [--ports 80 | 8000-8100]
//	wirenetctl rule list NET | delete NET RULE
//	wirenetctl policy NET               (the flows the rules leave open)
//	wirenetctl interface list NET | revoke IFACE
//	wirenetctl host create NAME [--endpoint ADDR:PORT] [--network NET]...
//	wirenetctl host list | delete HOST  (delete revokes its interfaces)
//	wirenetctl host scope HOST --network NET... | --global
//	wirenetctl admin create NAME --network NET...
//	wirenetctl admin list | delete ADMIN | scope ADMIN --network NET...
//	wirenetctl relay create NAME --address LOCAL[=ADVERTISED] [--address ...] --ports LO-HI --probe-port N
//	wirenetctl relay list | delete RELAY
//	wirenetctl device create NET SVC --gateway IFACE [--ttl 24h] [--out FILE]
//	wirenetctl attach NAME NET SVC [--member M [--replace]]   (local agent)
//	wirenetctl detach IFACE             (local agent)
//	wirenetctl interfaces | status      (local agent)
//
// A rule's FROM or TO may be '*', every service but the one on the other
// side, and TO may be internet.
//
// QUOTA is any of --interfaces N, --services N, --rules N and --edges N,
// each bounding what the network holds. A network's creation gives each
// bound it leaves out the control plane's default; quota set replaces the
// whole quota, a bound left out unbounded.
//
// A host created with --network may attach only into those networks; one
// without is global. Rescoping a host revokes its interfaces in the networks
// it loses. An admin token manages only the networks it names: their
// services, rules, interfaces and development machines, and hosts scoped
// within them.
//
// An attach with --member holds that name among the service's members, so
// M.SVC.NET.internal resolves to the workload's own address; --replace
// revokes the name's current holder.
//
// The control plane is $WIRENET_CP, authenticated by $WIRENET_ADMIN_TOKEN,
// the operator's token or an admin token; the agent's socket is
// $WIRENET_AGENT_SOCKET.
package main

import (
	"context"
	"crypto/rand"
	"encoding/json"
	"errors"
	"flag"
	"fmt"
	"net/netip"
	"os"
	"strings"
	"time"

	"github.com/danthegoodman1/wirenet/internal/agent/localapi"
	"github.com/danthegoodman1/wirenet/internal/api"
	"github.com/danthegoodman1/wirenet/internal/cpclient"
	"github.com/danthegoodman1/wirenet/internal/devconf"
	"github.com/danthegoodman1/wirenet/internal/model"
)

func main() {
	if err := run(os.Args[1:]); err != nil {
		fmt.Fprintln(os.Stderr, "wirenetctl:", err)
		os.Exit(1)
	}
}

func usage() error {
	return errors.New("usage: wirenetctl network|quota|service|rule|policy|interface|host|admin|relay|attach|detach|interfaces|status ...; see the package documentation")
}

func run(args []string) error {
	if len(args) == 0 {
		return usage()
	}
	ctx, cancel := context.WithTimeout(context.Background(), 2*time.Minute)
	defer cancel()
	switch args[0] {
	case "attach", "detach", "interfaces", "status":
		return local(ctx, args)
	}
	if len(args) < 2 {
		return usage()
	}
	c, err := cpclient.New(env("WIRENET_CP", "http://127.0.0.1:8443"), os.Getenv("WIRENET_ADMIN_TOKEN"), cpclient.Options{CAFile: os.Getenv("WIRENET_CA_FILE")})
	if err != nil {
		return err
	}
	if args[0] == "policy" {
		if len(args) != 2 {
			return usage()
		}
		return show(c.Policy(ctx, args[1]))
	}
	verb, rest := args[0]+" "+args[1], args[2:]
	fs := flag.NewFlagSet(verb, flag.ContinueOnError)
	switch verb {
	case "network create":
		p6 := fs.String("prefix6", "", "IPv6 prefix, a random ULA /64 by default")
		p4 := fs.String("prefix4", "", "IPv4 prefix for services that opt in")
		mtu := fs.Int("mtu", 0, "overlay MTU")
		relays := fs.String("relays", "", "relay names or identifiers, in preference order")
		quota := quotaFlags(fs)
		name, err := parse(fs, rest, 1)
		if err != nil {
			return err
		}
		req := api.CreateNetwork{Name: name[0], MTU: *mtu, Quota: *quota}
		if req.Prefix6, err = optPrefix(*p6); err != nil {
			return err
		}
		if req.Prefix4, err = optPrefix(*p4); err != nil {
			return err
		}
		if *relays != "" {
			if req.Relays, err = relayIDs(ctx, c, strings.Split(*relays, ",")); err != nil {
				return err
			}
		}
		return show(c.CreateNetwork(ctx, req))
	case "network list":
		return show(c.Networks(ctx))
	case "network get":
		a, err := parse(fs, rest, 1)
		if err != nil {
			return err
		}
		return show(c.Network(ctx, a[0]))
	case "network delete":
		a, err := parse(fs, rest, 1)
		if err != nil {
			return err
		}
		return c.DeleteNetwork(ctx, a[0])
	case "quota show":
		a, err := parse(fs, rest, 1)
		if err != nil {
			return err
		}
		return show(c.Quota(ctx, a[0]))
	case "quota set":
		quota := quotaFlags(fs)
		a, err := parse(fs, rest, 1)
		if err != nil {
			return err
		}
		return show(c.SetQuota(ctx, a[0], *quota))
	case "service create":
		ipv4 := fs.Bool("ipv4", false, "give the service an IPv4 address too")
		mode := fs.String("mode", "", "flip (default) or cutover")
		a, err := parse(fs, rest, 2)
		if err != nil {
			return err
		}
		return show(c.CreateService(ctx, a[0], api.CreateService{Name: a[1], IPv4: *ipv4, Mode: api.Mode(*mode)}))
	case "service list":
		a, err := parse(fs, rest, 1)
		if err != nil {
			return err
		}
		return show(c.Services(ctx, a[0]))
	case "service delete":
		a, err := parse(fs, rest, 2)
		if err != nil {
			return err
		}
		return c.DeleteService(ctx, a[0], a[1])
	case "rule create":
		proto := fs.String("proto", "tcp", "tcp, udp or any")
		ports := fs.String("ports", "", "a port or a range, all ports when empty")
		deny := fs.Bool("deny", false, "take the flows out of every allow")
		a, err := parse(fs, rest, 3)
		if err != nil {
			return err
		}
		var pr model.PortRange
		if *ports != "" {
			if pr, err = model.ParsePortRange(*ports); err != nil {
				return err
			}
		}
		action := api.Allow
		if *deny {
			action = api.Deny
		}
		return show(c.CreateRule(ctx, a[0], api.CreateRule{From: a[1], To: a[2], Proto: model.Proto(*proto), Ports: pr, Action: action}))
	case "rule list":
		a, err := parse(fs, rest, 1)
		if err != nil {
			return err
		}
		return show(c.Rules(ctx, a[0]))
	case "rule delete":
		a, err := parse(fs, rest, 2)
		if err != nil {
			return err
		}
		return c.DeleteRule(ctx, a[0], model.RuleID(a[1]))
	case "interface list":
		a, err := parse(fs, rest, 1)
		if err != nil {
			return err
		}
		return show(c.Interfaces(ctx, a[0]))
	case "interface revoke":
		a, err := parse(fs, rest, 1)
		if err != nil {
			return err
		}
		return c.Revoke(ctx, model.InterfaceID(a[0]))
	case "host create":
		endpoint := fs.String("endpoint", "", "where development machines reach a gateway on this host")
		var nets stringList
		fs.Var(&nets, "network", "a network the host may attach into, repeatable; none makes it global")
		a, err := parse(fs, rest, 1)
		if err != nil {
			return err
		}
		req := api.CreateHost{Name: a[0], Networks: nets}
		if *endpoint != "" {
			if req.Endpoint, err = netip.ParseAddrPort(*endpoint); err != nil {
				return err
			}
		}
		return show(c.CreateHost(ctx, req))
	case "host list":
		return show(c.Hosts(ctx))
	case "host scope":
		var nets stringList
		fs.Var(&nets, "network", "a network the host may attach into, repeatable")
		global := fs.Bool("global", false, "let the host attach into every network")
		a, err := parse(fs, rest, 1)
		if err != nil {
			return err
		}
		if *global == (len(nets) > 0) {
			return errors.New("host scope: give --global or at least one --network")
		}
		return show(c.SetHostScope(ctx, a[0], api.Scope{Global: *global, Networks: nets}))
	case "host delete":
		a, err := parse(fs, rest, 1)
		if err != nil {
			return err
		}
		return c.DeleteHost(ctx, a[0])
	case "admin create":
		var nets stringList
		fs.Var(&nets, "network", "a network the token manages, repeatable")
		a, err := parse(fs, rest, 1)
		if err != nil {
			return err
		}
		return show(c.CreateAdmin(ctx, api.CreateAdmin{Name: a[0], Networks: nets}))
	case "admin list":
		return show(c.Admins(ctx))
	case "admin scope":
		var nets stringList
		fs.Var(&nets, "network", "a network the token manages, repeatable")
		a, err := parse(fs, rest, 1)
		if err != nil {
			return err
		}
		return show(c.SetAdminScope(ctx, a[0], nets))
	case "admin delete":
		a, err := parse(fs, rest, 1)
		if err != nil {
			return err
		}
		return c.DeleteAdmin(ctx, a[0])
	case "relay create":
		var addrs addrList
		fs.Var(&addrs, "address", "LOCAL[=ADVERTISED], repeatable")
		ports := fs.String("ports", "", "the port range edges draw from, LO-HI")
		probe := fs.Uint("probe-port", 0, "the port agents probe on the first address")
		a, err := parse(fs, rest, 1)
		if err != nil {
			return err
		}
		pr, err := model.ParsePortRange(*ports)
		if err != nil {
			return fmt.Errorf("--ports: %w", err)
		}
		return show(c.CreateRelay(ctx, api.CreateRelay{Name: a[0], Addresses: addrs, PortLo: pr.Lo, PortHi: pr.Hi, ProbePort: uint16(*probe)}))
	case "relay list":
		return show(c.Relays(ctx))
	case "relay delete":
		a, err := parse(fs, rest, 1)
		if err != nil {
			return err
		}
		return c.DeleteRelay(ctx, a[0])
	case "device create":
		gateway := fs.String("gateway", "", "the gateway interface the machine peers with")
		ttl := fs.Duration("ttl", 24*time.Hour, "the lease's fixed term; generate a new config to extend it")
		out := fs.String("out", "", "write the wg-quick config here instead of stdout")
		a, err := parse(fs, rest, 2)
		if err != nil {
			return err
		}
		// The key is minted here and never sent: the control plane sees
		// its public half alone.
		priv, err := model.NewPrivateKey(rand.Reader)
		if err != nil {
			return err
		}
		cfg, err := c.CreateDevice(ctx, a[0], api.CreateDevice{Service: a[1], Gateway: model.InterfaceID(*gateway), PublicKey: priv.Public(), TTL: *ttl})
		if err != nil {
			return err
		}
		text := devconf.WGQuick(priv, cfg)
		if *out == "" {
			_, err = os.Stdout.WriteString(text)
			return err
		}
		return os.WriteFile(*out, []byte(text), 0o600)
	}
	return usage()
}

// local drives the agent on this host.
func local(ctx context.Context, args []string) error {
	c := localapi.NewClient(env("WIRENET_AGENT_SOCKET", "/run/wirenet/agent.sock"))
	fs := flag.NewFlagSet(args[0], flag.ContinueOnError)
	switch args[0] {
	case "attach":
		kind := fs.String("kind", "", "workload (default) or gateway")
		member := fs.String("member", "", "a name to hold among the service's members")
		replace := fs.Bool("replace", false, "revoke the member's current holder")
		a, err := parse(fs, args[1:], 3)
		if err != nil {
			return err
		}
		if *replace && *member == "" {
			return errors.New("attach: --replace needs --member")
		}
		return show(c.Attach(ctx, api.LocalAttach{
			Name: a[0], Network: a[1], Service: a[2], Kind: api.Kind(*kind), Member: *member, Replace: *replace,
		}))
	case "detach":
		a, err := parse(fs, args[1:], 1)
		if err != nil {
			return err
		}
		return show(c.Detach(ctx, model.InterfaceID(a[0])))
	case "interfaces":
		return show(c.Interfaces(ctx))
	case "status":
		return show(c.Status(ctx))
	}
	return usage()
}

func parse(fs *flag.FlagSet, args []string, n int) ([]string, error) {
	// Flags may follow the positional arguments.
	var pos []string
	for len(args) > 0 {
		if err := fs.Parse(args); err != nil {
			return nil, err
		}
		args = fs.Args()
		if len(args) > 0 {
			pos = append(pos, args[0])
			args = args[1:]
		}
	}
	if len(pos) != n {
		return nil, fmt.Errorf("%s: want %d arguments, got %d", fs.Name(), n, len(pos))
	}
	return pos, nil
}

func show[T any](v T, err error) error {
	if err != nil {
		return err
	}
	enc := json.NewEncoder(os.Stdout)
	enc.SetIndent("", "  ")
	return enc.Encode(v)
}

func env(name, def string) string {
	if v := os.Getenv(name); v != "" {
		return v
	}
	return def
}

func optPrefix(s string) (netip.Prefix, error) {
	if s == "" {
		return netip.Prefix{}, nil
	}
	return netip.ParsePrefix(s)
}

// relayIDs resolves relay names to identifiers, passing identifiers
// through.
func relayIDs(ctx context.Context, c *cpclient.Client, refs []string) ([]model.RelayID, error) {
	relays, err := c.Relays(ctx)
	if err != nil {
		return nil, err
	}
	var out []model.RelayID
	for _, ref := range refs {
		found := false
		for _, r := range relays {
			if string(r.ID) == ref || r.Name == ref {
				out = append(out, r.ID)
				found = true
				break
			}
		}
		if !found {
			return nil, fmt.Errorf("no relay %q", ref)
		}
	}
	return out, nil
}

type addrList []api.RelayAddress

func (a *addrList) String() string { return fmt.Sprint(*a) }

func (a *addrList) Set(s string) error {
	local, adv, ok := strings.Cut(s, "=")
	l, err := netip.ParseAddr(local)
	if err != nil {
		return err
	}
	ra := api.RelayAddress{Local: l, Advertised: l}
	if ok {
		if ra.Advertised, err = netip.ParseAddr(adv); err != nil {
			return err
		}
	}
	*a = append(*a, ra)
	return nil
}

// stringList is a repeatable flag.
type stringList []string

func (l *stringList) String() string { return strings.Join(*l, ",") }

func (l *stringList) Set(s string) error {
	*l = append(*l, s)
	return nil
}

// quotaFlags registers a quota's bounds on fs.
func quotaFlags(fs *flag.FlagSet) *api.Quota {
	var q api.Quota
	fs.IntVar(&q.Interfaces, "interfaces", 0, "the most live interfaces the network holds")
	fs.IntVar(&q.Services, "services", 0, "the most services the network holds")
	fs.IntVar(&q.Rules, "rules", 0, "the most rules the network holds")
	fs.IntVar(&q.Edges, "edges", 0, "the most edges the network holds, each two ports on every relay of its set")
	return &q
}
