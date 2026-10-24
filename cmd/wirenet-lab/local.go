//go:build linux

package main

import (
	"context"
	"crypto/rand"
	"errors"
	"fmt"
	"net/netip"
	"net/url"
	"os"
	"os/exec"
	"path/filepath"
	"strconv"
	"strings"
	"sync"
	"syscall"
	"time"

	"github.com/jackc/pgx/v5"

	"github.com/danthegoodman1/wirenet/internal/lab"
	"github.com/danthegoodman1/wirenet/internal/model"
)

// labName prefixes every namespace, link and unit the local environment
// makes. Labs on one machine take turns under the lab package's lock, which
// this environment holds from Up to Down.
const labName = "wnl"

// cpTelemetry is where the lab's control plane serves metrics.
const cpTelemetry = "http://10.213.255.1:19090"

// localEnv runs the fleet as namespaces on this machine, with the real
// daemons, through internal/lab.
type localEnv struct {
	localOptions

	lab      *lab.Lab
	dir      string
	dropDB   func()
	labHosts map[string]*lab.Host
	relays   map[string]*lab.Relay
	nodes    struct {
		cp, mid       Node
		hosts, relays []Node
	}
	mu    sync.Mutex
	procs []*localProc
}

func newLocalEnv(o localOptions) (Env, error) {
	if os.Geteuid() != 0 {
		return nil, errors.New("the local environment needs root")
	}
	if o.hosts < 2 {
		return nil, errors.New("the local environment needs at least 2 hosts")
	}
	for _, b := range []string{"wirenet-cp", "wirenet-agent", "wirenet-relay", "wirenetctl", "wirenet-bench", "hostbench"} {
		if _, err := os.Stat(filepath.Join(o.bin, b)); err != nil {
			return nil, fmt.Errorf("%s: build the binaries into --bin first (scripts/lab does): %w", b, err)
		}
	}
	e := &localEnv{localOptions: o}
	// Names and addresses are fixed before Up, so a plan's dry run and its
	// report agree with what Up builds.
	e.nodes.cp = Node{Name: "cp", Role: RoleCP, Addr: netip.MustParseAddr("10.213.255.1")}
	return e, nil
}

func (e *localEnv) Name() string  { return "local" }
func (e *localEnv) DryRun() bool  { return false }
func (e *localEnv) CP() Node      { return e.nodes.cp }
func (e *localEnv) Hosts() []Node { return e.nodes.hosts }
func (e *localEnv) Relays() []Node {
	return e.nodes.relays
}
func (e *localEnv) Middle() Node           { return e.nodes.mid }
func (e *localEnv) Bin(name string) string { return filepath.Join(e.bin, name) }
func (e *localEnv) AgentSocket(n Node) string {
	return e.labHosts[n.Name].Socket
}
func (e *localEnv) NamespacePrefix(n Node) string { return e.labHosts[n.Name].Prefix }
func (e *localEnv) ScratchNS(n Node) string       { return labName + "x" + n.Name }

// Up builds a lab. The lab always runs the whole fleet, so it holds the
// machine's lab lock even for plans that use no daemon.
func (e *localEnv) Up(ctx context.Context, _ bool) error {
	dir, err := os.MkdirTemp("", "wirenet-lab-")
	if err != nil {
		return err
	}
	e.dir = dir
	store := e.store
	if store != "memory" {
		if store, e.dropDB, err = freshSchema(ctx, store); err != nil {
			return err
		}
	}
	l, err := lab.New(lab.Options{
		Name: labName, Dir: dir, Bin: e.bin, Store: store, LogLevel: e.logLevel,
		RelayPorts: model.PortRange{Lo: 10000, Hi: 60000}, Log: e.log,
	})
	if err != nil {
		return err
	}
	e.lab = l
	e.labHosts, e.relays = map[string]*lab.Host{}, map[string]*lab.Relay{}
	e.nodes.hosts, e.nodes.relays = nil, nil
	// The relays keep their production socket buffers; the kernel caps
	// them at net.core.rmem_max, which the report records.
	relayArgs := []string{"--socket-buffer", strconv.Itoa(8 << 20)}
	for _, name := range []string{"mid", "r1", "r2"} {
		r, err := l.AddRelay(ctx, name, relayArgs...)
		if err != nil {
			return fmt.Errorf("relay %s: %w", name, err)
		}
		e.relays[name] = r
		n := Node{Name: name, Role: RoleRelay, Addr: r.Addr}
		if name == "mid" {
			n.Role = RoleMiddle
			e.nodes.mid = n
		} else {
			e.nodes.relays = append(e.nodes.relays, n)
		}
	}
	for i := 1; i <= e.hosts; i++ {
		name := "h" + strconv.Itoa(i)
		h, err := l.AddHost(ctx, name)
		if err != nil {
			return fmt.Errorf("host %s: %w", name, err)
		}
		e.labHosts[name] = h
		e.nodes.hosts = append(e.nodes.hosts, Node{Name: name, Role: RoleAgent, Addr: h.Addr})
	}
	return nil
}

func (e *localEnv) Down(ctx context.Context) error {
	e.mu.Lock()
	procs := e.procs
	e.procs = nil
	e.mu.Unlock()
	var errs []error
	for _, p := range procs {
		errs = append(errs, p.Stop(ctx))
	}
	if e.lab != nil {
		e.lab.Close()
		e.lab = nil
	}
	if e.dropDB != nil {
		e.dropDB()
		e.dropDB = nil
	}
	if e.dir != "" {
		if e.keep != "" {
			errs = append(errs, keepLogs(e.dir, filepath.Join(e.keep, time.Now().UTC().Format("20060102-150405"))))
		}
		errs = append(errs, os.RemoveAll(e.dir))
	}
	return errors.Join(errs...)
}

// Logs returns the tail of every daemon's log.
func (e *localEnv) Logs(lines int) string {
	if e.lab == nil {
		return ""
	}
	return e.lab.Logs(lines)
}

// keepLogs copies a lab directory's logs.
func keepLogs(from, to string) error {
	logs, err := filepath.Glob(filepath.Join(from, "*.log"))
	if err != nil {
		return err
	}
	for _, l := range logs {
		b, err := os.ReadFile(l)
		if err != nil {
			return err
		}
		if err := writeFileUnderSudo(filepath.Join(to, filepath.Base(l)), b); err != nil {
			return err
		}
	}
	return nil
}

// command runs argv in n's namespace. nsenter switches the network
// namespace alone, so the namespaces agents bind-mount stay visible.
func (e *localEnv) command(ctx context.Context, n Node, argv []string) (*exec.Cmd, error) {
	if n.Role == RoleCP {
		return exec.CommandContext(ctx, argv[0], argv[1:]...), nil
	}
	ns := ""
	if h, ok := e.labHosts[n.Name]; ok {
		ns = h.NS
	} else if r, ok := e.relays[n.Name]; ok {
		ns = r.NS
	} else {
		return nil, fmt.Errorf("no node %q", n.Name)
	}
	return exec.CommandContext(ctx, "nsenter", append([]string{"--net=/run/netns/" + ns, "--"}, argv...)...), nil
}

func (e *localEnv) Exec(ctx context.Context, n Node, argv ...string) ([]byte, error) {
	cmd, err := e.command(ctx, n, argv)
	if err != nil {
		return nil, err
	}
	return output(cmd, n.Name)
}

type localProc struct {
	cmd  *exec.Cmd
	done chan struct{}
	err  error
}

func (e *localEnv) Spawn(ctx context.Context, n Node, argv ...string) (Stopper, error) {
	// The process outlives ctx: Stop or Down ends it.
	cmd, err := e.command(context.WithoutCancel(ctx), n, argv)
	if err != nil {
		return nil, err
	}
	logPath := filepath.Join(e.dir, fmt.Sprintf("spawn-%s-%d.log", n.Name, time.Now().UnixNano()))
	f, err := os.Create(logPath)
	if err != nil {
		return nil, err
	}
	cmd.Stdout, cmd.Stderr = f, f
	cmd.SysProcAttr = &syscall.SysProcAttr{Setpgid: true, Pdeathsig: syscall.SIGKILL}
	if err := cmd.Start(); err != nil {
		f.Close()
		return nil, err
	}
	p := &localProc{cmd: cmd, done: make(chan struct{})}
	go func() {
		p.err = cmd.Wait()
		f.Close()
		close(p.done)
	}()
	e.mu.Lock()
	e.procs = append(e.procs, p)
	e.mu.Unlock()
	return p, nil
}

// Stop ends the process with SIGTERM, then SIGKILL.
func (p *localProc) Stop(ctx context.Context) error {
	select {
	case <-p.done:
		return nil
	default:
	}
	if err := syscall.Kill(-p.cmd.Process.Pid, syscall.SIGTERM); err != nil && !errors.Is(err, syscall.ESRCH) {
		return err
	}
	select {
	case <-p.done:
	case <-time.After(5 * time.Second):
		syscall.Kill(-p.cmd.Process.Pid, syscall.SIGKILL)
		<-p.done
	}
	return nil
}

func (e *localEnv) Ctl(ctx context.Context, n Node, args ...string) ([]byte, error) {
	cmd := exec.CommandContext(ctx, e.Bin("wirenetctl"), args...)
	cmd.Env = append(os.Environ(), "WIRENET_CP="+e.lab.CPURL, "WIRENET_ADMIN_TOKEN="+e.lab.Token)
	if isAgentCommand(args) {
		h, ok := e.labHosts[n.Name]
		if !ok {
			return nil, fmt.Errorf("%s runs no agent", n.Name)
		}
		cmd.Env = append(cmd.Env, "WIRENET_AGENT_SOCKET="+h.Socket)
	}
	return output(cmd, n.Name)
}

func (e *localEnv) OperatorAPI() (string, []string) {
	return e.lab.CPURL, []string{"--token", e.lab.Token}
}

func (e *localEnv) Metrics(ctx context.Context, n Node) (string, error) {
	switch {
	case n.Role == RoleCP:
		return lab.Metrics(cpTelemetry)
	case e.labHosts[n.Name] != nil:
		return lab.Metrics(e.labHosts[n.Name].Telemetry)
	case e.relays[n.Name] != nil:
		return lab.Metrics(e.relays[n.Name].Telemetry)
	}
	return "", fmt.Errorf("no node %q", n.Name)
}

func (e *localEnv) StopRelay(ctx context.Context, n Node) error {
	r, ok := e.relays[n.Name]
	if !ok {
		return fmt.Errorf("no relay %q", n.Name)
	}
	r.Kill()
	return nil
}

func (e *localEnv) StartRelay(ctx context.Context, n Node) error {
	r, ok := e.relays[n.Name]
	if !ok {
		return fmt.Errorf("no relay %q", n.Name)
	}
	return r.Start()
}

func (e *localEnv) Substrate(ctx context.Context) (Substrate, error) {
	out, err := exec.CommandContext(ctx, "sh", "-c", probeScript).Output()
	if err != nil {
		return Substrate{}, fmt.Errorf("probing this machine: %w", err)
	}
	m := parseMachine("every node", out)
	store := "memory"
	if e.store != "memory" {
		store = "postgres"
	}
	return Substrate{Env: "local", Region: "local", InstanceTypes: map[Role]string{"all": "local"}, Store: store, Nodes: []Machine{m}}, nil
}

// freshSchema creates an empty schema in the database dsn names and returns
// a DSN whose connections use it, and a function that drops it.
func freshSchema(ctx context.Context, dsn string) (string, func(), error) {
	u, err := url.Parse(dsn)
	if err != nil || (u.Scheme != "postgres" && u.Scheme != "postgresql") {
		return "", nil, fmt.Errorf("--store wants memory or a postgres:// URL: %q", dsn)
	}
	schema := "wirenetlab_" + strings.ToLower(rand.Text())
	exec := func(sql string) error {
		conn, err := pgx.Connect(ctx, dsn)
		if err != nil {
			return err
		}
		_, err = conn.Exec(ctx, sql)
		return errors.Join(err, conn.Close(ctx))
	}
	if err := exec("CREATE SCHEMA " + schema); err != nil {
		return "", nil, fmt.Errorf("creating a schema: %w", err)
	}
	q := u.Query()
	q.Set("search_path", schema)
	u.RawQuery = q.Encode()
	drop := func() {
		if err := exec("DROP SCHEMA " + schema + " CASCADE"); err != nil {
			fmt.Fprintf(os.Stderr, "wirenet-lab: dropping schema %s: %v\n", schema, err)
		}
	}
	return u.String(), drop, nil
}
