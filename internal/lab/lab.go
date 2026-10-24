//go:build linux

// Package lab builds a whole deployment inside one Linux kernel: an
// underlay namespace holding a bridge, a namespace per host and per relay
// attached to it, and the real wirenet-cp, wirenet-relay and wirenet-agent processes,
// one per role. The end-to-end tests run on it, and so do the benchmark
// plans when no cloud is at hand.
//
// The control plane runs in the caller's namespace, reached over a veth
// from the underlay, so it can use a database on the caller's loopback.
// The underlay forwards between its own interfaces, so the caller's
// firewall sees only the control plane's traffic, on input.
package lab

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"net"
	"net/http"
	"net/netip"
	"os"
	"os/exec"
	"path/filepath"
	"runtime"
	"strconv"
	"strings"
	"sync"
	"syscall"
	"time"

	"github.com/vishvananda/netns"
	"golang.org/x/net/dns/dnsmessage"

	"github.com/danthegoodman1/wirenet/internal/agent/localapi"
	"github.com/danthegoodman1/wirenet/internal/api"
	"github.com/danthegoodman1/wirenet/internal/cpclient"
	"github.com/danthegoodman1/wirenet/internal/model"
)

// Options configure a lab.
type Options struct {
	// Name prefixes every namespace, link and file; at most 6 characters.
	Name string
	// Dir holds binaries' logs, credentials, journals and state.
	Dir string
	// Bin holds wirenet-cp, wirenet-agent and wirenet-relay.
	Bin string
	// Store is wirenet-cp's --store.
	Store string
	// CPArgs are extra wirenet-cp flags, such as short lease clocks.
	CPArgs []string
	// LogLevel is every daemon's --log-level; debug when empty.
	LogLevel string
	// RelayPorts is the range each relay draws edge ports from;
	// 20000-29999 when zero.
	RelayPorts model.PortRange
	// Log receives a line per step.
	Log io.Writer
}

// Lab is one deployment.
type Lab struct {
	opts   Options
	Admin  *cpclient.Client
	CPURL  string
	Token  string
	net    string // the underlay namespace
	cp     *Proc
	hosts  []*Host
	relays []*Relay
	nextIP byte
	mu     sync.Mutex
	procs  []*Proc
	units  []unitLog
	lock   *os.File
	born   time.Time
}

// lockPath is the lock every lab holds while it exists.
const lockPath = "/run/lock/wirenet-lab.lock"

// Underlay addressing. Internet4 and Internet6 stand for the internet: the
// underlay namespace answers them.
var (
	Internet4  = netip.MustParseAddr("203.0.113.1")
	Internet6  = netip.MustParseAddr("2001:db8::1")
	underlay6  = netip.MustParsePrefix("fd13:213::/64")
	cpLink     = netip.MustParsePrefix("10.213.255.0/30")
	cpRoot     = netip.MustParseAddr("10.213.255.1")
	cpUnderlay = netip.MustParseAddr("10.213.255.2")
	bridgeAddr = netip.MustParseAddr("10.213.0.1")
)

const adminToken = "lab-admin-token-0123456789abcdef"

// Build checks for binaries in dir, building them from the module when
// missing, and returns dir.
func Build(dir string) (string, error) {
	if err := os.MkdirAll(dir, 0o755); err != nil {
		return "", err
	}
	root, err := moduleRoot()
	if err != nil {
		return "", err
	}
	cmd := exec.Command("go", "build", "-o", dir+"/", "./cmd/wirenet-cp", "./cmd/wirenet-agent", "./cmd/wirenet-relay", "./cmd/wirenetctl")
	cmd.Dir = root
	if out, err := cmd.CombinedOutput(); err != nil {
		return "", fmt.Errorf("go build: %v\n%s", err, out)
	}
	return dir, nil
}

func moduleRoot() (string, error) {
	_, file, _, _ := runtime.Caller(0)
	dir := filepath.Dir(file)
	for dir != "/" {
		if _, err := os.Stat(filepath.Join(dir, "go.mod")); err == nil {
			return dir, nil
		}
		dir = filepath.Dir(dir)
	}
	return "", errors.New("no go.mod above the lab package")
}

// New builds the underlay and starts the control plane.
func New(opts Options) (*Lab, error) {
	if os.Geteuid() != 0 {
		return nil, errors.New("the lab needs root")
	}
	if len(opts.Name) == 0 || len(opts.Name) > 6 {
		return nil, errors.New("lab name must be 1 to 6 characters")
	}
	if opts.Log == nil {
		opts.Log = io.Discard
	}
	if opts.Store == "" {
		opts.Store = "memory"
	}
	if opts.LogLevel == "" {
		opts.LogLevel = "debug"
	}
	if opts.RelayPorts == (model.PortRange{}) {
		opts.RelayPorts = model.PortRange{Lo: 20000, Hi: 29999}
	}
	// Every lab uses the same underlay addresses, so labs on one machine
	// take turns.
	lock, err := os.OpenFile(lockPath, os.O_RDWR|os.O_CREATE, 0o644)
	if err != nil {
		return nil, err
	}
	if err := syscall.Flock(int(lock.Fd()), syscall.LOCK_EX); err != nil {
		lock.Close()
		return nil, fmt.Errorf("lab lock: %w", err)
	}
	l := &Lab{opts: opts, net: opts.Name + "net", nextIP: 10, Token: adminToken, lock: lock, born: time.Now()}
	l.Purge()
	if err := l.underlay(); err != nil {
		l.Close()
		return nil, err
	}
	if err := l.startCP(); err != nil {
		l.Close()
		return nil, err
	}
	return l, nil
}

func (l *Lab) logf(format string, args ...any) {
	fmt.Fprintf(l.opts.Log, "lab %6.3fs: "+format+"\n", append([]any{time.Since(l.born).Seconds()}, args...)...)
}

// sh runs a command and returns its error with its output.
func sh(args ...string) error {
	out, err := exec.Command(args[0], args[1:]...).CombinedOutput()
	if err != nil {
		return fmt.Errorf("%s: %v: %s", strings.Join(args, " "), err, strings.TrimSpace(string(out)))
	}
	return nil
}

func nsh(ns string, args ...string) error {
	return sh(append([]string{"ip", "netns", "exec", ns}, args...)...)
}

func (l *Lab) underlay() error {
	cpLinkRoot, cpLinkNS := l.opts.Name+"cp", l.opts.Name+"cpu"
	steps := [][]string{
		{"ip", "netns", "add", l.net},
		{"ip", "-n", l.net, "link", "set", "lo", "up"},
		// A bridge with no address of its own takes its lowest port's,
		// which changes as nodes join (br_stp_recalculate_bridge_id), and
		// routes only frames sent to its current address: br_handle_frame
		// marks those alone PACKET_HOST, and ip_rcv_core drops the rest. A
		// host that resolved the gateway before a lower address joined
		// would lose the underlay until its neighbour entry expired.
		{"ip", "-n", l.net, "link", "add", "br0", "address", "02:00:0a:d5:00:01", "type", "bridge"},
		{"ip", "-n", l.net, "addr", "add", bridgeAddr.String() + "/24", "dev", "br0"},
		{"ip", "-n", l.net, "addr", "add", "fd13:213::1/64", "dev", "br0", "nodad"},
		{"ip", "-n", l.net, "link", "set", "br0", "up"},
		{"ip", "netns", "exec", l.net, "sysctl", "-qw", "net.ipv4.ip_forward=1"},
		{"ip", "netns", "exec", l.net, "sysctl", "-qw", "net.ipv6.conf.all.forwarding=1"},
		{"ip", "link", "add", cpLinkRoot, "type", "veth", "peer", "name", cpLinkNS},
		{"ip", "link", "set", cpLinkNS, "netns", l.net},
		{"ip", "addr", "add", cpRoot.String() + "/30", "dev", cpLinkRoot},
		{"ip", "link", "set", cpLinkRoot, "up"},
		{"ip", "-n", l.net, "addr", "add", cpUnderlay.String() + "/30", "dev", cpLinkNS},
		{"ip", "-n", l.net, "link", "set", cpLinkNS, "up"},
		{"ip", "route", "add", "10.213.0.0/24", "via", cpUnderlay.String(), "dev", cpLinkRoot},
		// The internet, and a metadata service, as seen from the hosts.
		{"ip", "-n", l.net, "addr", "add", Internet4.String() + "/32", "dev", "lo"},
		{"ip", "-n", l.net, "addr", "add", Internet6.String() + "/128", "dev", "lo"},
		{"ip", "-n", l.net, "addr", "add", "169.254.169.254/32", "dev", "lo"},
		{"ip", "-n", l.net, "addr", "add", "fd00:ec2::254/128", "dev", "lo"},
	}
	for _, s := range steps {
		if err := sh(s...); err != nil {
			return err
		}
	}
	l.logf("underlay %s up", l.net)
	return nil
}

// Proc is one daemon.
type Proc struct {
	Name string
	Log  string
	cmd  *exec.Cmd
	done chan struct{} // closed once the process is reaped
}

func (l *Lab) spawn(name, ns string, args ...string) (*Proc, error) {
	logPath := filepath.Join(l.opts.Dir, name+".log")
	f, err := os.OpenFile(logPath, os.O_WRONLY|os.O_CREATE|os.O_APPEND, 0o644)
	if err != nil {
		return nil, err
	}
	if ns != "" {
		// nsenter switches the network namespace alone. ip netns exec
		// would also give the daemon a mount namespace of its own, hiding
		// the namespaces an agent bind-mounts under /run/netns.
		args = append([]string{"nsenter", "--net=/run/netns/" + ns, "--"}, args...)
	}
	cmd := exec.Command(args[0], args[1:]...)
	cmd.Stdout, cmd.Stderr = f, f
	cmd.Env = append(os.Environ(), "WIRENET_ADMIN_TOKEN="+adminToken)
	cmd.SysProcAttr = &syscall.SysProcAttr{Setpgid: true, Pdeathsig: syscall.SIGKILL}
	if err := cmd.Start(); err != nil {
		f.Close()
		return nil, err
	}
	p := &Proc{Name: name, Log: logPath, cmd: cmd, done: make(chan struct{})}
	go func() { cmd.Wait(); f.Close(); close(p.done) }()
	l.mu.Lock()
	l.procs = append(l.procs, p)
	l.mu.Unlock()
	l.logf("started %s (pid %d)", name, cmd.Process.Pid)
	return p, nil
}

// Stop sends SIGTERM and waits, then kills.
func (p *Proc) Stop() {
	if p.Exited() {
		return
	}
	syscall.Kill(-p.cmd.Process.Pid, syscall.SIGTERM)
	select {
	case <-p.done:
	case <-time.After(5 * time.Second):
		syscall.Kill(-p.cmd.Process.Pid, syscall.SIGKILL)
		<-p.done
	}
}

// Kill kills at once, as a crash does.
func (p *Proc) Kill() {
	if p.Exited() {
		return
	}
	syscall.Kill(-p.cmd.Process.Pid, syscall.SIGKILL)
	<-p.done
}

// Exited reports whether the process has ended.
func (p *Proc) Exited() bool {
	select {
	case <-p.done:
		return true
	default:
		return false
	}
}

// Tail returns the last lines of the process's log.
func (p *Proc) Tail(n int) string {
	b, _ := os.ReadFile(p.Log)
	lines := strings.Split(strings.TrimRight(string(b), "\n"), "\n")
	if len(lines) > n {
		lines = lines[len(lines)-n:]
	}
	return strings.Join(lines, "\n")
}

func (l *Lab) bin(name string) string { return filepath.Join(l.opts.Bin, name) }

func (l *Lab) startCP() error {
	addr := netip.AddrPortFrom(cpRoot, 18443)
	args := append([]string{l.bin("wirenet-cp"), "--listen", addr.String(), "--telemetry", netip.AddrPortFrom(cpRoot, 19090).String(),
		"--store", l.opts.Store, "--log-format", "json", "--log-level", l.opts.LogLevel}, l.opts.CPArgs...)
	p, err := l.spawn("cp", "", args...)
	if err != nil {
		return err
	}
	l.cp = p
	l.CPURL = "http://" + addr.String()
	l.Admin, err = cpclient.New(l.CPURL, adminToken, cpclient.Options{})
	if err != nil {
		return err
	}
	return waitHTTP("http://"+netip.AddrPortFrom(cpRoot, 19090).String()+"/healthz", 10*time.Second, p)
}

// RestartCP stops the control plane and starts it again on the same store.
func (l *Lab) RestartCP() error {
	l.cp.Stop()
	return l.startCP()
}

// Underlay names the underlay namespace, where the internet answers.
func (l *Lab) Underlay() string { return l.net }

// CPTelemetry is the control plane's metrics and health address.
func (l *Lab) CPTelemetry() string { return "http://" + netip.AddrPortFrom(cpRoot, 19090).String() }

// CP returns the control plane's process.
func (l *Lab) CP() *Proc { return l.cp }

func waitHTTP(url string, d time.Duration, p *Proc) error {
	deadline := time.Now().Add(d)
	for time.Now().Before(deadline) {
		if p != nil && p.Exited() {
			return fmt.Errorf("%s exited:\n%s", p.Name, p.Tail(20))
		}
		resp, err := http.Get(url)
		if err == nil {
			resp.Body.Close()
			if resp.StatusCode == http.StatusOK {
				return nil
			}
		}
		time.Sleep(50 * time.Millisecond)
	}
	return fmt.Errorf("nothing answered %s", url)
}

// node is a namespace on the underlay.
type node struct {
	NS    string
	Addr  netip.Addr
	Addr6 netip.Addr
}

func (l *Lab) addNode(name string) (node, error) {
	l.mu.Lock()
	l.nextIP++
	ip := l.nextIP
	l.mu.Unlock()
	n := node{
		NS:    l.opts.Name + name,
		Addr:  netip.AddrFrom4([4]byte{10, 213, 0, ip}),
		Addr6: netip.AddrFrom16([16]byte{0xfd, 0x13, 0x02, 0x13, 15: ip}),
	}
	link := l.opts.Name + name
	steps := [][]string{
		{"ip", "netns", "add", n.NS},
		{"ip", "-n", n.NS, "link", "set", "lo", "up"},
		{"ip", "-n", l.net, "link", "add", link, "type", "veth", "peer", "name", "eth0", "netns", n.NS},
		{"ip", "-n", l.net, "link", "set", link, "master", "br0", "up"},
		{"ip", "-n", n.NS, "addr", "add", n.Addr.String() + "/24", "dev", "eth0"},
		{"ip", "-n", n.NS, "addr", "add", n.Addr6.String() + "/64", "dev", "eth0", "nodad"},
		{"ip", "-n", n.NS, "link", "set", "eth0", "up"},
		{"ip", "-n", n.NS, "route", "add", "default", "via", bridgeAddr.String()},
		{"ip", "-n", n.NS, "-6", "route", "add", "default", "via", "fd13:213::1"},
		// Hosts forward IPv6 as hostprep leaves them, so egress serves it.
		{"ip", "netns", "exec", n.NS, "sysctl", "-qw", "net.ipv6.conf.all.forwarding=1"},
	}
	for _, s := range steps {
		if err := sh(s...); err != nil {
			return n, err
		}
	}
	return n, nil
}

// Relay is one relay node.
type Relay struct {
	node
	Name      string
	ID        model.RelayID
	Probe     netip.AddrPort
	Telemetry string
	Proc      *Proc
	creds     string
	state     string
	lab       *Lab
	args      []string
}

// AddRelay registers a relay with the control plane and starts it. args
// are extra wirenet-relay flags.
func (l *Lab) AddRelay(ctx context.Context, name string, args ...string) (*Relay, error) {
	n, err := l.addNode(name)
	if err != nil {
		return nil, err
	}
	r := &Relay{node: n, Name: name, Probe: netip.AddrPortFrom(n.Addr, 7000), lab: l, args: args}
	creds, err := l.Admin.CreateRelay(ctx, api.CreateRelay{
		Name: name, Addresses: []api.RelayAddress{{Local: n.Addr, Advertised: n.Addr}},
		PortLo: l.opts.RelayPorts.Lo, PortHi: l.opts.RelayPorts.Hi, ProbePort: 7000,
	})
	if err != nil {
		return nil, err
	}
	r.ID = model.RelayID(creds.ID)
	r.creds = filepath.Join(l.opts.Dir, name+".json")
	r.state = filepath.Join(l.opts.Dir, name+"-state")
	if err := writeJSON(r.creds, creds); err != nil {
		return nil, err
	}
	l.relays = append(l.relays, r)
	return r, r.Start()
}

// Kill kills the relay, as a crash does.
func (r *Relay) Kill() { r.Proc.Kill() }

// Start starts the relay's process.
func (r *Relay) Start() error {
	r.Telemetry = "http://" + netip.AddrPortFrom(r.Addr, 9092).String()
	args := append([]string{r.lab.bin("wirenet-relay"), "--cp", r.lab.CPURL, "--credentials", r.creds,
		"--state", r.state, "--probe", r.Probe.String(), "--telemetry", netip.AddrPortFrom(r.Addr, 9092).String(),
		"--log-format", "json", "--log-level", r.lab.opts.LogLevel, "--socket-buffer", "0"}, r.args...)
	p, err := r.lab.spawn(r.Name, r.NS, args...)
	if err != nil {
		return err
	}
	r.Proc = p
	err = waitHTTP(r.Telemetry+"/readyz", 10*time.Second, p)
	r.lab.logf("%s ready", r.Name)
	return err
}

// Host is one agent host.
type Host struct {
	node
	Name      string
	ID        model.HostID
	Socket    string
	Prefix    string
	Telemetry string
	Agent     *Proc
	// Unit names the agent's systemd unit when systemd runs it.
	Unit  string
	Local *localapi.Client
	// NATNS and Public are the NAT in front of a host behind one, and the
	// address it translates to.
	NATNS    string
	Public   netip.Addr
	endpoint netip.AddrPort
	creds    string
	journal  string
	lab      *Lab
	args     []string
	// by registers the host, and networks scopes it; a host the operator
	// registers with no networks is global.
	by       *cpclient.Client
	networks []string
}

// AddHost registers a host and starts its agent. args are extra wirenet-agent
// flags.
func (l *Lab) AddHost(ctx context.Context, name string, args ...string) (*Host, error) {
	n, err := l.addNode(name)
	if err != nil {
		return nil, err
	}
	h := &Host{node: n, Name: name, Prefix: l.opts.Name + name + "w", lab: l, args: args}
	return h, l.register(ctx, h)
}

// AddGatewayHost registers a host development machines can reach, at its
// underlay address, and starts its agent.
func (l *Lab) AddGatewayHost(ctx context.Context, name string, args ...string) (*Host, error) {
	n, err := l.addNode(name)
	if err != nil {
		return nil, err
	}
	h := &Host{node: n, Name: name, Prefix: l.opts.Name + name + "w", lab: l, args: args, endpoint: netip.AddrPortFrom(n.Addr, 0)}
	return h, l.register(ctx, h)
}

// AddHostAs registers a host through an admin client, the operator's or an
// admin token's, scoped to networks, and starts its agent.
func (l *Lab) AddHostAs(ctx context.Context, by *cpclient.Client, name string, networks []string, args ...string) (*Host, error) {
	n, err := l.addNode(name)
	if err != nil {
		return nil, err
	}
	h := &Host{node: n, Name: name, Prefix: l.opts.Name + name + "w", lab: l, args: args, by: by, networks: networks}
	return h, l.register(ctx, h)
}

// Client returns a client of the control plane holding a token.
func (l *Lab) Client(token string) (*cpclient.Client, error) {
	return cpclient.New(l.CPURL, token, cpclient.Options{})
}

func (l *Lab) register(ctx context.Context, h *Host) error {
	by := h.by
	if by == nil {
		by = l.Admin
	}
	creds, err := by.CreateHost(ctx, api.CreateHost{Name: h.Name, Endpoint: h.endpoint, Networks: h.networks})
	if err != nil {
		return err
	}
	h.ID = model.HostID(creds.ID)
	h.creds = filepath.Join(l.opts.Dir, h.Name+".json")
	h.journal = filepath.Join(l.opts.Dir, h.Name+"-journal")
	h.Socket = filepath.Join(l.opts.Dir, h.Name+".sock")
	if err := writeJSON(h.creds, creds); err != nil {
		return err
	}
	h.Local = localapi.NewClient(h.Socket)
	l.hosts = append(l.hosts, h)
	return h.Start()
}

// Start starts the host's agent.
func (h *Host) Start() error {
	h.Telemetry = "http://" + netip.AddrPortFrom(h.Addr, 9091).String()
	args := append([]string{h.lab.bin("wirenet-agent"), "--cp", h.lab.CPURL, "--credentials", h.creds,
		"--journal", h.journal, "--socket", h.Socket, "--telemetry", netip.AddrPortFrom(h.Addr, 9091).String(),
		"--prefix", h.Prefix, "--log-format", "json", "--log-level", h.lab.opts.LogLevel}, h.args...)
	if h.Unit != "" {
		return h.startUnit(args)
	}
	p, err := h.lab.spawn(h.Name, h.NS, args...)
	if err != nil {
		return err
	}
	h.Agent = p
	err = waitHTTP(h.Telemetry+"/readyz", 15*time.Second, p)
	h.lab.logf("%s ready", h.Name)
	return err
}

// NAT shapes the address translation in front of a host.
type NAT struct {
	// UDPTimeout is how long a UDP mapping outlives its last packet, in
	// both conntrack states.
	UDPTimeout time.Duration
	// Random gives every new mapping a random public port, as a NAT that
	// reassigns ports does.
	Random bool
}

// AddHostBehindNAT registers a host whose underlay traffic leaves through
// a NAT namespace, and starts its agent.
func (l *Lab) AddHostBehindNAT(ctx context.Context, name string, nat NAT, args ...string) (*Host, error) {
	gw, err := l.addNode(name + "n")
	if err != nil {
		return nil, err
	}
	l.mu.Lock()
	l.nextIP++
	k := l.nextIP
	l.mu.Unlock()
	inner := netip.PrefixFrom(netip.AddrFrom4([4]byte{192, 168, k, 0}), 24)
	gwIn := netip.AddrFrom4([4]byte{192, 168, k, 1})
	host := netip.AddrFrom4([4]byte{192, 168, k, 2})
	ns := l.opts.Name + name
	masq := "masquerade"
	if nat.Random {
		masq = "masquerade random"
	}
	timeout := strconv.Itoa(max(int(nat.UDPTimeout/time.Second), 1))
	steps := [][]string{
		{"ip", "netns", "add", ns},
		{"ip", "-n", ns, "link", "set", "lo", "up"},
		{"ip", "-n", gw.NS, "link", "add", "in0", "type", "veth", "peer", "name", "eth0", "netns", ns},
		{"ip", "-n", gw.NS, "addr", "add", gwIn.String() + "/24", "dev", "in0"},
		{"ip", "-n", gw.NS, "link", "set", "in0", "up"},
		{"ip", "-n", ns, "addr", "add", host.String() + "/24", "dev", "eth0"},
		{"ip", "-n", ns, "link", "set", "eth0", "up"},
		{"ip", "-n", ns, "route", "add", "default", "via", gwIn.String()},
		{"ip", "netns", "exec", gw.NS, "sysctl", "-qw", "net.ipv4.ip_forward=1"},
		{"ip", "netns", "exec", gw.NS, "nft", "add table ip nat; add chain ip nat post { type nat hook postrouting priority srcnat; }; " +
			"add rule ip nat post ip saddr " + inner.String() + " oif eth0 " + masq},
		// Conntrack's UDP clocks are per namespace once a rule loads it.
		{"ip", "netns", "exec", gw.NS, "sysctl", "-qw", "net.netfilter.nf_conntrack_udp_timeout=" + timeout},
		{"ip", "netns", "exec", gw.NS, "sysctl", "-qw", "net.netfilter.nf_conntrack_udp_timeout_stream=" + timeout},
		// The caller reaches the agent's telemetry through the underlay;
		// connections it opens are never translated.
		{"ip", "-n", l.net, "route", "add", inner.String(), "via", gw.Addr.String()},
		{"ip", "route", "add", inner.String(), "via", cpUnderlay.String(), "dev", l.opts.Name + "cp"},
	}
	for _, st := range steps {
		if err := sh(st...); err != nil {
			return nil, err
		}
	}
	h := &Host{node: node{NS: ns, Addr: host}, Name: name, Prefix: l.opts.Name + name + "w", lab: l, args: args, NATNS: gw.NS, Public: gw.Addr}
	return h, l.register(ctx, h)
}

// FlushNAT drops every mapping the host's NAT holds, as a NAT that reboots
// or rebinds does.
func (h *Host) FlushNAT() error {
	return nsh(h.NATNS, "conntrack", "-F")
}

// Restart kills the agent, as a crash does, and starts it again.
func (h *Host) Restart() error {
	if h.Unit != "" {
		// systemd restarts the unit, handing it the descriptors it stored.
		if err := sh("systemctl", "kill", "--signal=KILL", "--kill-whom=main", h.Unit); err != nil {
			return err
		}
		time.Sleep(100 * time.Millisecond)
		return waitHTTP(h.Telemetry+"/readyz", 15*time.Second, nil)
	}
	h.Agent.Kill()
	return h.Start()
}

// AddSystemdHost registers a host whose agent runs as a transient systemd
// service with a descriptor store and Restart=always, as in production.
func (l *Lab) AddSystemdHost(ctx context.Context, name string, args ...string) (*Host, error) {
	n, err := l.addNode(name)
	if err != nil {
		return nil, err
	}
	h := &Host{node: n, Name: name, Prefix: l.opts.Name + name + "w", lab: l, args: args, Unit: l.opts.Name + "-" + name + "-agent"}
	return h, l.register(ctx, h)
}

func (h *Host) startUnit(args []string) error {
	logPath := filepath.Join(h.lab.opts.Dir, h.Name+".log")
	// nsenter rather than NetworkNamespacePath=, which would give the
	// agent a mount namespace of its own and hide the namespaces it
	// bind-mounts; nsenter execs, so the agent stays the main process.
	run := []string{"systemd-run", "--unit=" + h.Unit, "--collect",
		"-p", "Restart=always", "-p", "RestartSec=300ms",
		"-p", "NotifyAccess=main", "-p", "FileDescriptorStoreMax=65536", "-p", "FileDescriptorStorePreserve=yes",
		"-p", "StandardOutput=append:" + logPath, "-p", "StandardError=append:" + logPath,
		"--", "nsenter", "--net=/run/netns/" + h.NS, "--"}
	if err := sh(append(run, args...)...); err != nil {
		return err
	}
	h.lab.mu.Lock()
	h.lab.units = append(h.lab.units, unitLog{unit: h.Unit, log: logPath})
	h.lab.mu.Unlock()
	h.lab.logf("started unit %s", h.Unit)
	return waitHTTP(h.Telemetry+"/readyz", 15*time.Second, nil)
}

type unitLog struct{ unit, log string }

// AttachGateway asks the host's agent for a gateway interface.
func (h *Host) AttachGateway(ctx context.Context, name, network, service string) (api.LocalInterface, error) {
	return h.Local.Attach(ctx, api.LocalAttach{Name: name, Network: network, Service: service, Kind: api.Gateway})
}

// Detach asks the host's agent to tear an interface down.
func (h *Host) Detach(ctx context.Context, id model.InterfaceID) (api.LocalInterface, error) {
	return h.Local.Detach(ctx, id)
}

// Namespaces lists the workload namespaces the host's agent has named.
func (h *Host) Namespaces() []string {
	names, _ := filepath.Glob("/run/netns/" + h.Prefix + "*")
	for i, n := range names {
		names[i] = filepath.Base(n)
	}
	return names
}

// DevicePorts lists the UDP ports kernel sockets hold in the host's
// namespace: every WireGuard device's, and nothing a process opened.
func (h *Host) DevicePorts() ([]uint16, error) {
	out, err := exec.Command("ip", "netns", "exec", h.NS, "ss", "-Hulnp").Output()
	if err != nil {
		return nil, err
	}
	var ports []uint16
	for _, line := range strings.Split(string(out), "\n") {
		f := strings.Fields(line)
		if len(f) < 4 || strings.Contains(line, "users:") {
			continue
		}
		if i := strings.LastIndex(f[3], ":"); i >= 0 {
			if p, err := strconv.ParseUint(f[3][i+1:], 10, 16); err == nil {
				ports = append(ports, uint16(p))
			}
		}
	}
	return ports, nil
}

// Attach asks the host's agent for an interface.
func (h *Host) Attach(ctx context.Context, name, network, service string) (api.LocalInterface, error) {
	return h.Local.Attach(ctx, api.LocalAttach{Name: name, Network: network, Service: service})
}

// AttachMember asks the host's agent for an interface holding a member
// name, revoking its holder if replace is set.
func (h *Host) AttachMember(ctx context.Context, name, network, service, member string, replace bool) (api.LocalInterface, error) {
	return h.Local.Attach(ctx, api.LocalAttach{Name: name, Network: network, Service: service, Member: member, Replace: replace})
}

func writeJSON(path string, v any) error {
	b, err := json.Marshal(v)
	if err != nil {
		return err
	}
	return os.WriteFile(path, b, 0o600)
}

// Close stops every process and removes everything the lab made.
func (l *Lab) Close() {
	l.mu.Lock()
	procs := l.procs
	l.mu.Unlock()
	for i := len(procs) - 1; i >= 0; i-- {
		procs[i].Stop()
	}
	l.Purge()
	l.lock.Close()
}

// Purge removes every namespace and link named for the lab, including
// those a crashed run left behind, and kills processes still inside them.
func (l *Lab) Purge() {
	units, _ := exec.Command("systemctl", "list-units", "--all", "--plain", "--no-legend", l.opts.Name+"-*").Output()
	for _, line := range strings.Split(string(units), "\n") {
		if f := strings.Fields(line); len(f) > 0 {
			exec.Command("systemctl", "stop", f[0]).Run()
			exec.Command("systemctl", "reset-failed", f[0]).Run()
		}
	}
	names, _ := filepath.Glob("/run/netns/" + l.opts.Name + "*")
	for _, path := range names {
		ns := filepath.Base(path)
		out, _ := exec.Command("ip", "netns", "pids", ns).Output()
		for _, pid := range strings.Fields(string(out)) {
			exec.Command("kill", "-9", pid).Run()
		}
	}
	for _, path := range names {
		exec.Command("ip", "netns", "del", filepath.Base(path)).Run()
	}
	exec.Command("ip", "link", "del", l.opts.Name+"cp").Run()
	exec.Command("ip", "route", "del", "10.213.0.0/24").Run()
}

// InNS runs fn on a thread inside a namespace. Sockets fn opens stay in it.
func InNS(name string, fn func() error) error {
	runtime.LockOSThread()
	defer runtime.UnlockOSThread()
	root, err := netns.Get()
	if err != nil {
		return err
	}
	defer root.Close()
	h, err := netns.GetFromName(name)
	if err != nil {
		return err
	}
	defer h.Close()
	if err := netns.Set(h); err != nil {
		return err
	}
	ferr := fn()
	if err := netns.Set(root); err != nil {
		// The thread stays locked and dies with the goroutine, rather than
		// carrying the wrong namespace back to the scheduler.
		runtime.LockOSThread()
		return errors.Join(ferr, err)
	}
	return ferr
}

// Serve accepts TCP connections in a namespace and answers each with reply.
func Serve(ns string, addr netip.AddrPort, reply string) (net.Listener, error) {
	var ln net.Listener
	err := InNS(ns, func() error {
		var err error
		ln, err = net.Listen("tcp", addr.String())
		return err
	})
	if err != nil {
		return nil, err
	}
	go func() {
		for {
			c, err := ln.Accept()
			if err != nil {
				return
			}
			go func() {
				defer c.Close()
				io.WriteString(c, reply)
				io.Copy(io.Discard, c)
			}()
		}
	}()
	return ln, nil
}

// Dial connects from a namespace and reads the server's first answer.
func Dial(ns string, addr netip.AddrPort, timeout time.Duration) (string, error) {
	var c net.Conn
	err := InNS(ns, func() error {
		var err error
		c, err = net.DialTimeout("tcp", addr.String(), timeout)
		return err
	})
	if err != nil {
		return "", err
	}
	defer c.Close()
	c.SetReadDeadline(time.Now().Add(timeout))
	b := make([]byte, 256)
	n, err := c.Read(b)
	return string(b[:n]), err
}

// DialUntil retries Dial until it answers or d passes.
func DialUntil(ns string, addr netip.AddrPort, d time.Duration) (string, error) {
	deadline := time.Now().Add(d)
	var last error
	for time.Now().Before(deadline) {
		got, err := Dial(ns, addr, time.Second)
		if err == nil {
			return got, nil
		}
		last = err
		time.Sleep(100 * time.Millisecond)
	}
	return "", fmt.Errorf("no answer from %v within %v: %w", addr, d, last)
}

// Metrics fetches a daemon's metrics text.
func Metrics(url string) (string, error) {
	resp, err := http.Get(url + "/metrics")
	if err != nil {
		return "", err
	}
	defer resp.Body.Close()
	b, err := io.ReadAll(resp.Body)
	return string(b), err
}

// Logs returns every process's log tail, for a failing test.
func (l *Lab) Logs(n int) string {
	l.mu.Lock()
	defer l.mu.Unlock()
	var b strings.Builder
	for _, p := range l.procs {
		fmt.Fprintf(&b, "==== %s\n%s\n", p.Name, p.Tail(n))
	}
	for _, u := range l.units {
		p := Proc{Name: u.unit, Log: u.log}
		fmt.Fprintf(&b, "==== %s\n%s\n", u.unit, p.Tail(n))
	}
	return b.String()
}

// Lookup asks a namespace's stub resolver one question and returns the
// answer's addresses and response code.
func Lookup(ns, name string, typ dnsmessage.Type) ([]netip.Addr, dnsmessage.RCode, error) {
	return LookupWithin(ns, name, typ, 2*time.Second)
}

// LookupWithin is Lookup, waiting up to d for the answer.
func LookupWithin(ns, name string, typ dnsmessage.Type, d time.Duration) ([]netip.Addr, dnsmessage.RCode, error) {
	return lookup(ns, netip.MustParseAddrPort("127.0.0.53:53"), name, typ, d)
}

func lookup(ns string, server netip.AddrPort, name string, typ dnsmessage.Type, d time.Duration) ([]netip.Addr, dnsmessage.RCode, error) {
	q := dnsmessage.Message{
		Header:    dnsmessage.Header{ID: 1, RecursionDesired: true},
		Questions: []dnsmessage.Question{{Name: dnsmessage.MustNewName(name), Type: typ, Class: dnsmessage.ClassINET}},
	}
	b, err := q.Pack()
	if err != nil {
		return nil, 0, err
	}
	var c *net.UDPConn
	if err := InNS(ns, func() error {
		var err error
		c, err = net.DialUDP("udp", nil, net.UDPAddrFromAddrPort(server))
		return err
	}); err != nil {
		return nil, 0, err
	}
	defer c.Close()
	c.SetDeadline(time.Now().Add(d))
	if _, err := c.Write(b); err != nil {
		return nil, 0, err
	}
	buf := make([]byte, 1500)
	n, err := c.Read(buf)
	if err != nil {
		return nil, 0, err
	}
	var m dnsmessage.Message
	if err := m.Unpack(buf[:n]); err != nil {
		return nil, 0, err
	}
	var out []netip.Addr
	for _, a := range m.Answers {
		switch r := a.Body.(type) {
		case *dnsmessage.AResource:
			out = append(out, netip.AddrFrom4(r.A))
		case *dnsmessage.AAAAResource:
			out = append(out, netip.AddrFrom16(r.AAAA))
		}
	}
	return out, m.RCode, nil
}

// Laptop is a development machine on the underlay running a stock
// WireGuard client.
type Laptop struct {
	NS   string
	Addr netip.Addr
}

// AddLaptop builds a namespace on the underlay and brings up a wg-quick
// config in it with the stock tools, as wg-quick would, but for DNS:
// queries go to the config's resolver explicitly.
func (l *Lab) AddLaptop(name, config string) (*Laptop, error) {
	n, err := l.addNode(name)
	if err != nil {
		return nil, err
	}
	conf := filepath.Join(l.opts.Dir, name+".conf")
	if err := os.WriteFile(conf, []byte(config), 0o600); err != nil {
		return nil, err
	}
	// What wg-quick strip does: wg setconf takes the file without the
	// lines wg-quick itself handles.
	var kept []string
	for _, line := range strings.Split(config, "\n") {
		k, _, _ := strings.Cut(line, " = ")
		switch k {
		case "Address", "DNS", "MTU", "Table", "PreUp", "PostUp", "PreDown", "PostDown", "SaveConfig":
			continue
		}
		kept = append(kept, line)
	}
	stripped := []byte(strings.Join(kept, "\n"))
	// wg's AppArmor profile reads configs from /etc/wireguard alone.
	if err := os.MkdirAll("/etc/wireguard", 0o700); err != nil {
		return nil, err
	}
	wgconf := filepath.Join("/etc/wireguard", l.opts.Name+"-"+name+".conf")
	if err := os.WriteFile(wgconf, stripped, 0o600); err != nil {
		return nil, err
	}
	defer os.Remove(wgconf)
	steps := [][]string{
		{"ip", "-n", n.NS, "link", "add", "wg0", "type", "wireguard"},
		{"ip", "netns", "exec", n.NS, "wg", "setconf", "wg0", wgconf},
	}
	var addrs, routes []string
	for _, line := range strings.Split(config, "\n") {
		k, v, ok := strings.Cut(line, " = ")
		if !ok {
			continue
		}
		for _, part := range strings.Split(v, ", ") {
			switch k {
			case "Address":
				addrs = append(addrs, part)
			case "AllowedIPs":
				routes = append(routes, part)
			case "MTU":
				steps = append(steps, []string{"ip", "-n", n.NS, "link", "set", "wg0", "mtu", part})
			}
		}
	}
	for _, a := range addrs {
		steps = append(steps, []string{"ip", "-n", n.NS, "addr", "add", a, "dev", "wg0"})
	}
	steps = append(steps, []string{"ip", "-n", n.NS, "link", "set", "wg0", "up"})
	for _, r := range routes {
		steps = append(steps, []string{"ip", "-n", n.NS, "route", "add", r, "dev", "wg0"})
	}
	for _, st := range steps {
		if err := sh(st...); err != nil {
			return nil, err
		}
	}
	lp := &Laptop{NS: n.NS}
	if len(addrs) > 0 {
		p, err := netip.ParsePrefix(addrs[0])
		if err == nil {
			lp.Addr = p.Addr()
		}
	}
	return lp, nil
}

// ServeRemote accepts TCP connections in a namespace and answers each with
// the address it came from, so a test sees the source a server sees.
func ServeRemote(ns string, addr netip.AddrPort) (net.Listener, error) {
	var ln net.Listener
	if err := InNS(ns, func() error {
		var err error
		ln, err = net.Listen("tcp", addr.String())
		return err
	}); err != nil {
		return nil, err
	}
	go func() {
		for {
			c, err := ln.Accept()
			if err != nil {
				return
			}
			go func() {
				defer c.Close()
				ap, _ := netip.ParseAddrPort(c.RemoteAddr().String())
				io.WriteString(c, ap.Addr().Unmap().String())
				io.Copy(io.Discard, c)
			}()
		}
	}()
	return ln, nil
}

// LookupAt asks a resolver at server, from a namespace, one question.
func LookupAt(ns string, server netip.Addr, name string, typ dnsmessage.Type) ([]netip.Addr, dnsmessage.RCode, error) {
	return lookup(ns, netip.AddrPortFrom(server, 53), name, typ, 2*time.Second)
}

// Exec runs a command inside a namespace.
func Exec(ns string, args ...string) error {
	return nsh(ns, args...)
}

// LogLines returns a process's JSON log lines whose message is msg, as
// decoded objects.
func (p *Proc) LogLines(msg string) []map[string]any {
	b, _ := os.ReadFile(p.Log)
	var out []map[string]any
	for _, line := range strings.Split(string(b), "\n") {
		var m map[string]any
		if json.Unmarshal([]byte(line), &m) == nil && m["message"] == msg {
			out = append(out, m)
		}
	}
	return out
}
