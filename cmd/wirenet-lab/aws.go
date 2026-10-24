package main

import (
	"bytes"
	"context"
	"encoding/json"
	"fmt"
	"io"
	"io/fs"
	"net/netip"
	"os"
	"os/exec"
	"path"
	"path/filepath"
	"strconv"
	"strings"
	"sync"
	"sync/atomic"

	"github.com/danthegoodman1/wirenet/deploy"
)

// Fleet is the "fleet" output of deploy/aws/terraform.
type Fleet struct {
	Region        string          `json:"region"`
	SSHUser       string          `json:"ssh_user"`
	InstanceTypes map[Role]string `json:"instance_types"`
	CP            Instance        `json:"cp"`
	Agents        []Instance      `json:"agents"`
	Relays        []Instance      `json:"relays"`
	Middle        Instance        `json:"middle"`
}

// Instance is one EC2 instance.
type Instance struct {
	Name      string `json:"name"`
	PublicIP  string `json:"public_ip"`
	PrivateIP string `json:"private_ip"`
}

// readFleet reads `terraform output -json` and returns its fleet.
func readFleet(file string) (Fleet, error) {
	var f Fleet
	b, err := os.ReadFile(file)
	if err != nil {
		return f, err
	}
	var outputs map[string]struct {
		Value json.RawMessage `json:"value"`
	}
	if err := json.Unmarshal(b, &outputs); err != nil {
		return f, fmt.Errorf("%s: %w", file, err)
	}
	v, ok := outputs["fleet"]
	if !ok {
		return f, fmt.Errorf("%s has no fleet output; write it with terraform output -json", file)
	}
	if err := json.Unmarshal(v.Value, &f); err != nil {
		return f, fmt.Errorf("%s: fleet: %w", file, err)
	}
	if len(f.Agents) < 2 || len(f.Relays) < 2 {
		return f, fmt.Errorf("%s: the plans need 2 agent hosts and 2 relays, the fleet has %d and %d", file, len(f.Agents), len(f.Relays))
	}
	for _, in := range append(append([]Instance{f.CP, f.Middle}, f.Agents...), f.Relays...) {
		if _, err := netip.ParseAddr(in.PublicIP); err != nil {
			return f, fmt.Errorf("%s: %s: public address: %w", file, in.Name, err)
		}
		if _, err := netip.ParseAddr(in.PrivateIP); err != nil {
			return f, fmt.Errorf("%s: %s: private address: %w", file, in.Name, err)
		}
	}
	if f.SSHUser == "" {
		f.SSHUser = "ubuntu"
	}
	return f, nil
}

// Where things live on a fleet machine, and the ports its daemons use.
const (
	remoteBin   = "/usr/local/bin"
	remoteLib   = "/usr/local/lib/wirenet"
	cpPort      = 8443
	probePort   = 7000
	relayPorts  = "10000-60000"
	remoteStage = "/tmp/wirenet-deploy"
)

// telemetryPort is where each role's daemon serves metrics.
var telemetryPort = map[Role]int{RoleCP: 9090, RoleAgent: 9091, RoleRelay: 9092, RoleMiddle: 9092}

// roleBinaries are the binaries each role runs.
var roleBinaries = map[Role][]string{
	RoleCP:     {"wirenet-cp", "wirenetctl", "wirenet-bench"},
	RoleAgent:  {"wirenet-agent", "wirenetctl", "wirenet-bench", "hostbench"},
	RoleRelay:  {"wirenet-relay", "wirenet-bench"},
	RoleMiddle: {"wirenet-relay", "wirenet-bench"},
}

// extraBinaries are binaries a role takes when --bin holds them: etcd for
// the members plan.
var extraBinaries = map[Role][]string{
	RoleAgent: {"etcd", "etcdctl"},
}

// awsEnv runs plans against EC2 instances over ssh. In a dry run it prints
// every remote command and answers with stand-in output, so the whole
// flow runs without credentials or instances.
type awsEnv struct {
	fleet Fleet
	key   string
	// knownHosts, when set, records the fleet's host keys apart from the
	// operator's own, since EC2 hands their addresses to others later.
	knownHosts string
	bin        string
	dry        bool
	out        io.Writer
	control    string
	public     map[string]string
	nodes      struct {
		cp, mid       Node
		hosts, relays []Node
	}
	seq  atomic.Int64
	fake fakes
	// outMu keeps lines that machines print at once whole.
	outMu sync.Mutex
}

func newAWSEnv(fleet Fleet, key, bin string, dry bool, out io.Writer) (*awsEnv, error) {
	e := &awsEnv{fleet: fleet, key: key, bin: bin, dry: dry, out: out, public: map[string]string{}}
	node := func(in Instance, role Role) Node {
		e.public[in.Name] = in.PublicIP
		return Node{Name: in.Name, Role: role, Addr: netip.MustParseAddr(in.PrivateIP)}
	}
	e.nodes.cp = node(fleet.CP, RoleCP)
	e.nodes.mid = node(fleet.Middle, RoleMiddle)
	for _, in := range fleet.Agents {
		e.nodes.hosts = append(e.nodes.hosts, node(in, RoleAgent))
	}
	for _, in := range fleet.Relays {
		e.nodes.relays = append(e.nodes.relays, node(in, RoleRelay))
	}
	// ssh multiplexes every command to a machine over one connection.
	dir, err := os.MkdirTemp("", "wirenetlab-ssh-")
	if err != nil {
		return nil, err
	}
	e.control = dir
	return e, nil
}

func (e *awsEnv) Name() string                { return "aws" }
func (e *awsEnv) DryRun() bool                { return e.dry }
func (e *awsEnv) CP() Node                    { return e.nodes.cp }
func (e *awsEnv) Hosts() []Node               { return e.nodes.hosts }
func (e *awsEnv) Relays() []Node              { return e.nodes.relays }
func (e *awsEnv) Middle() Node                { return e.nodes.mid }
func (e *awsEnv) Bin(name string) string      { return path.Join(remoteBin, name) }
func (e *awsEnv) AgentSocket(Node) string     { return "/run/wirenet/agent.sock" }
func (e *awsEnv) NamespacePrefix(Node) string { return "wirenet-" }
func (e *awsEnv) ScratchNS(n Node) string     { return "wnb-" + n.Name }
func (e *awsEnv) cpURL() string               { return fmt.Sprintf("http://%s:%d", e.nodes.cp.Addr, cpPort) }
func (e *awsEnv) machines() []Node {
	return append(append([]Node{e.nodes.cp, e.nodes.mid}, e.nodes.hosts...), e.nodes.relays...)
}
func (e *awsEnv) relaysAndMiddle() []Node {
	return append(append([]Node{}, e.nodes.relays...), e.nodes.mid)
}
func (e *awsEnv) target(n Node) string { return e.fleet.SSHUser + "@" + e.public[n.Name] }
func (e *awsEnv) logf(format string, a ...any) {
	e.outMu.Lock()
	defer e.outMu.Unlock()
	fmt.Fprintf(e.out, format+"\n", a...)
}
func (e *awsEnv) sshOptions() []string {
	opts := []string{"-o", "BatchMode=yes", "-o", "StrictHostKeyChecking=accept-new", "-o", "ConnectTimeout=15",
		"-o", "ServerAliveInterval=15", "-o", "ControlMaster=auto", "-o", "ControlPath=" + e.control + "/%C", "-o", "ControlPersist=300"}
	if e.key != "" {
		opts = append([]string{"-i", e.key}, opts...)
	}
	if e.knownHosts != "" {
		opts = append(opts, "-o", "UserKnownHostsFile="+e.knownHosts)
	}
	return opts
}

// remote runs a shell command on n. stdin, when set, feeds it; secret
// keeps stdin out of a dry run's output.
func (e *awsEnv) remote(ctx context.Context, n Node, script string, stdin []byte, secret bool) ([]byte, error) {
	if e.dry {
		if stdin != nil && !secret {
			e.logf("[%s %s] %s\n    with stdin:\n%s", n.Name, e.public[n.Name], script, indent(string(stdin), "      "))
		} else {
			e.logf("[%s %s] %s", n.Name, e.public[n.Name], script)
		}
		return nil, nil
	}
	cmd := exec.CommandContext(ctx, "ssh", append(e.sshOptions(), e.target(n), script)...)
	if stdin != nil {
		cmd.Stdin = bytes.NewReader(stdin)
	}
	return output(cmd, n.Name)
}

func indent(s, prefix string) string {
	lines := strings.Split(strings.TrimRight(s, "\n"), "\n")
	for i, l := range lines {
		lines[i] = prefix + l
	}
	return strings.Join(lines, "\n")
}

func (e *awsEnv) Exec(ctx context.Context, n Node, argv ...string) ([]byte, error) {
	out, err := e.remote(ctx, n, "sudo "+shellJoin(argv), nil, false)
	if e.dry {
		return e.fake.exec(argv), nil
	}
	return out, err
}

func (e *awsEnv) Ctl(ctx context.Context, n Node, args ...string) ([]byte, error) {
	if isAgentCommand(args) {
		out, err := e.remote(ctx, n, "sudo "+shellJoin(append([]string{e.Bin("wirenetctl")}, args...)), nil, false)
		if e.dry {
			return e.fake.ctl(args), nil
		}
		return out, err
	}
	// The operator's token stays on the control-plane machine.
	script := "sudo sh -c " + shellQuote(fmt.Sprintf(`WIRENET_CP=http://127.0.0.1:%d WIRENET_ADMIN_TOKEN=$(cat /etc/wirenet/admin-token) exec %s "$@"`, cpPort, e.Bin("wirenetctl"))) +
		" wirenetctl " + shellJoin(args)
	out, err := e.remote(ctx, e.nodes.cp, script, nil, false)
	if e.dry {
		return e.fake.ctl(args), nil
	}
	return out, err
}

func (e *awsEnv) OperatorAPI() (string, []string) {
	return fmt.Sprintf("http://127.0.0.1:%d", cpPort), []string{"--token-file", "/etc/wirenet/admin-token"}
}

// awsProc is a process systemd runs as a transient unit.
type awsProc struct {
	e    *awsEnv
	n    Node
	unit string
}

func (e *awsEnv) Spawn(ctx context.Context, n Node, argv ...string) (Stopper, error) {
	unit := fmt.Sprintf("wnb-%d-%d", os.Getpid(), e.seq.Add(1))
	_, err := e.remote(ctx, n, "sudo systemd-run --quiet --collect --unit="+unit+" -- "+shellJoin(argv), nil, false)
	if err != nil {
		return nil, err
	}
	return &awsProc{e: e, n: n, unit: unit}, nil
}

// Stop stops the unit and checks that it is gone, whether it ran to the
// end or was stopped.
func (p *awsProc) Stop(ctx context.Context) error {
	_, err := p.e.remote(ctx, p.n, "sudo systemctl stop "+p.unit+" 2>/dev/null; ! systemctl is-active --quiet "+p.unit, nil, false)
	return err
}

// writeFile writes content to a root-owned file on n. A secret's content
// never prints.
func (e *awsEnv) writeFile(ctx context.Context, n Node, file string, content []byte, secret bool) error {
	umask := "022"
	if secret {
		umask = "077"
	}
	script := "sudo sh -c " + shellQuote(fmt.Sprintf("umask %s; mkdir -p %s && cat > %s", umask, path.Dir(file), file))
	_, err := e.remote(ctx, n, script, content, secret)
	return err
}

func (e *awsEnv) waitReady(ctx context.Context, n Node, port int) error {
	_, err := e.Exec(ctx, n, "sh", "-c", fmt.Sprintf(
		"for i in $(seq 300); do curl -sf --max-time 1 http://127.0.0.1:%d/readyz >/dev/null && exit 0; sleep 0.1; done; echo not ready >&2; exit 1", port))
	return err
}

func (e *awsEnv) Metrics(ctx context.Context, n Node) (string, error) {
	out, err := e.Exec(ctx, n, "curl", "-sf", "--max-time", "10", fmt.Sprintf("http://127.0.0.1:%d/metrics", telemetryPort[n.Role]))
	return string(out), err
}

// StopRelay kills the relay and stops its unit before Restart=always can
// bring it back.
func (e *awsEnv) StopRelay(ctx context.Context, n Node) error {
	if _, err := e.Exec(ctx, n, "systemctl", "kill", "--signal=SIGKILL", "wirenet-relay"); err != nil {
		return err
	}
	_, err := e.Exec(ctx, n, "systemctl", "stop", "wirenet-relay")
	return err
}

func (e *awsEnv) StartRelay(ctx context.Context, n Node) error {
	if _, err := e.Exec(ctx, n, "systemctl", "start", "wirenet-relay"); err != nil {
		return err
	}
	return e.waitReady(ctx, n, telemetryPort[n.Role])
}

// Up purges every machine and, for a fleet, starts the control plane on an
// empty database, then registers and starts every relay and agent.
func (e *awsEnv) Up(ctx context.Context, fleet bool) error {
	if err := e.Purge(ctx); err != nil {
		return err
	}
	if !fleet {
		return nil
	}
	cp := e.nodes.cp
	if _, err := e.Exec(ctx, cp, "runuser", "-u", "postgres", "--", "psql", "-q", "-v", "ON_ERROR_STOP=1",
		"-c", "DROP DATABASE IF EXISTS wirenet WITH (FORCE)", "-c", "CREATE DATABASE wirenet OWNER wirenet"); err != nil {
		return fmt.Errorf("resetting the database: %w", err)
	}
	cpArgs := fmt.Sprintf("WIRENET_CP_ARGS=--listen :%d --telemetry :%d --admin-token-file /etc/wirenet/admin-token --log-format json\n", cpPort, telemetryPort[RoleCP])
	if err := e.writeFile(ctx, cp, "/etc/wirenet/cp.env", []byte(cpArgs), false); err != nil {
		return err
	}
	if _, err := e.Exec(ctx, cp, "systemctl", "restart", "wirenet-cp"); err != nil {
		return err
	}
	if err := e.waitReady(ctx, cp, telemetryPort[RoleCP]); err != nil {
		return fmt.Errorf("control plane: %w", err)
	}
	for _, n := range e.relaysAndMiddle() {
		creds, err := e.Ctl(ctx, cp, "relay", "create", n.Name, "--address", n.Addr.String(), "--ports", relayPorts, "--probe-port", strconv.Itoa(probePort))
		if err != nil {
			return fmt.Errorf("registering relay %s: %w", n.Name, err)
		}
		args := fmt.Sprintf("WIRENET_RELAY_ARGS=--cp %s --credentials /etc/wirenet/relay.json --state /var/lib/wirenet/relay --probe %s --telemetry :%d --log-format json\n",
			e.cpURL(), netip.AddrPortFrom(n.Addr, probePort), telemetryPort[n.Role])
		if err := e.startDaemon(ctx, n, "relay", creds, args); err != nil {
			return err
		}
	}
	for _, n := range e.nodes.hosts {
		creds, err := e.Ctl(ctx, cp, "host", "create", n.Name)
		if err != nil {
			return fmt.Errorf("registering host %s: %w", n.Name, err)
		}
		args := fmt.Sprintf("WIRENET_AGENT_ARGS=--cp %s --credentials /etc/wirenet/host.json --telemetry :%d --log-format json\n", e.cpURL(), telemetryPort[RoleAgent])
		if err := e.startDaemon(ctx, n, "agent", creds, args); err != nil {
			return err
		}
	}
	return nil
}

// startDaemon writes a daemon's credentials and flags, then starts it.
// what is "relay" or "agent"; credentials go to relay.json or host.json.
func (e *awsEnv) startDaemon(ctx context.Context, n Node, what string, creds []byte, env string) error {
	credFile := "/etc/wirenet/relay.json"
	if what == "agent" {
		credFile = "/etc/wirenet/host.json"
	}
	if err := e.writeFile(ctx, n, credFile, creds, true); err != nil {
		return err
	}
	if err := e.writeFile(ctx, n, "/etc/wirenet/"+what+".env", []byte(env), false); err != nil {
		return err
	}
	if _, err := e.Exec(ctx, n, "systemctl", "restart", "wirenet-"+what); err != nil {
		return err
	}
	if err := e.waitReady(ctx, n, telemetryPort[n.Role]); err != nil {
		return fmt.Errorf("%s on %s: %w", what, n.Name, err)
	}
	return nil
}

// Purge stops every daemon and removes what earlier runs left on every
// machine; deploy/purge.sh says what.
func (e *awsEnv) Purge(ctx context.Context) error {
	return forEach(e.machines(), func(n Node) error {
		out, err := e.Exec(ctx, n, path.Join(remoteLib, "purge.sh"))
		if s := strings.TrimSpace(string(out)); s != "" {
			e.logf("%s: %s", n.Name, s)
		}
		return err
	})
}

func (e *awsEnv) Down(ctx context.Context) error { return e.Purge(ctx) }

// Close ends the shared ssh connections.
func (e *awsEnv) Close() error {
	if !e.dry {
		for _, n := range e.machines() {
			exec.Command("ssh", append(e.sshOptions(), "-O", "exit", e.target(n))...).Run()
		}
	}
	return os.RemoveAll(e.control)
}

func (e *awsEnv) Substrate(ctx context.Context) (Substrate, error) {
	s := Substrate{Env: "aws", Region: e.fleet.Region, InstanceTypes: e.fleet.InstanceTypes, Store: "postgres on " + e.nodes.cp.Name}
	var mu sync.Mutex
	err := forEach(e.machines(), func(n Node) error {
		out, err := e.Exec(ctx, n, "sh", "-c", probeScript)
		if err != nil {
			return err
		}
		m := parseMachine(n.Name, out)
		mu.Lock()
		defer mu.Unlock()
		for i := range s.Nodes {
			if o := &s.Nodes[i]; o.Kernel == m.Kernel && o.CPU == m.CPU && o.CPUs == m.CPUs && o.RmemMax == m.RmemMax {
				o.Nodes = append(o.Nodes, n.Name)
				return nil
			}
		}
		s.Nodes = append(s.Nodes, m)
		return nil
	})
	return s, err
}

// Deploy copies each machine its role's binaries, the host preparation
// script, the purge script and the systemd units, runs host preparation,
// and configures Prometheus on the control-plane machine.
func (e *awsEnv) Deploy(ctx context.Context) error {
	stage, err := os.MkdirTemp("", "wirenetlab-deploy-")
	if err != nil {
		return err
	}
	defer os.RemoveAll(stage)
	if err := os.CopyFS(stage, deploy.Files); err != nil {
		return err
	}
	units, err := fs.Glob(deploy.Files, "systemd/*.service")
	if err != nil {
		return err
	}
	for i := range units {
		units[i] = filepath.Join(stage, units[i])
	}
	for _, bins := range roleBinaries {
		for _, b := range bins {
			if _, err := os.Stat(filepath.Join(e.bin, b)); err != nil && !e.dry {
				return fmt.Errorf("%s: build linux/amd64 binaries into --bin first (deploy/README.md): %w", b, err)
			}
		}
	}
	err = forEach(e.machines(), func(n Node) error {
		if _, err := e.remote(ctx, n, fmt.Sprintf("rm -rf %[1]s && mkdir -p %[1]s/bin %[1]s/systemd", remoteStage), nil, false); err != nil {
			return err
		}
		var bins []string
		for _, b := range roleBinaries[n.Role] {
			bins = append(bins, filepath.Join(e.bin, b))
		}
		for _, b := range extraBinaries[n.Role] {
			if _, err := os.Stat(filepath.Join(e.bin, b)); err == nil {
				bins = append(bins, filepath.Join(e.bin, b))
			}
		}
		if err := e.scp(ctx, n, bins, remoteStage+"/bin/"); err != nil {
			return err
		}
		if err := e.scp(ctx, n, []string{filepath.Join(stage, "hostprep.sh"), filepath.Join(stage, "purge.sh")}, remoteStage+"/"); err != nil {
			return err
		}
		if err := e.scp(ctx, n, units, remoteStage+"/systemd/"); err != nil {
			return err
		}
		_, err := e.remote(ctx, n, fmt.Sprintf("sudo install -m 0755 %[1]s/bin/* %[2]s/ && sudo install -D -m 0755 -t %[3]s %[1]s/hostprep.sh %[1]s/purge.sh && "+
			"sudo install -m 0644 -t /etc/systemd/system %[1]s/systemd/*.service && sudo systemctl daemon-reload && sudo %[3]s/hostprep.sh %[4]s",
			remoteStage, remoteBin, remoteLib, n.Role), nil, false)
		return err
	})
	if err != nil {
		return err
	}
	return e.monitoring(ctx)
}

func (e *awsEnv) scp(ctx context.Context, n Node, files []string, dest string) error {
	if e.dry {
		e.logf("[%s %s] scp %s -> %s", n.Name, e.public[n.Name], strings.Join(files, " "), dest)
		return nil
	}
	args := append(append(append(e.sshOptions(), "-q"), files...), e.target(n)+":"+dest)
	_, err := output(exec.CommandContext(ctx, "scp", args...), n.Name)
	return err
}

// monitoring points the control-plane machine's Prometheus at the fleet.
func (e *awsEnv) monitoring(ctx context.Context) error {
	cp := e.nodes.cp
	conf, err := deploy.Files.ReadFile("monitoring/prometheus.yml")
	if err != nil {
		return err
	}
	if err := e.writeFile(ctx, cp, "/etc/prometheus/prometheus.yml", conf, false); err != nil {
		return err
	}
	files, err := targets(e.fleet)
	if err != nil {
		return err
	}
	for _, name := range sortedKeys(files) {
		if err := e.writeFile(ctx, cp, "/etc/prometheus/wirenet/"+name, files[name], false); err != nil {
			return err
		}
	}
	_, err = e.Exec(ctx, cp, "systemctl", "restart", "prometheus")
	return err
}

// fakes answers a dry run's commands with output shaped like the real
// thing, so a plan runs through every step it would take.
type fakes struct {
	mu   sync.Mutex
	next int
}

func (f *fakes) n() int {
	f.mu.Lock()
	defer f.mu.Unlock()
	f.next++
	return f.next
}

func (f *fakes) ctl(args []string) []byte {
	if len(args) == 0 {
		return []byte("{}")
	}
	verb := args[0]
	if len(args) > 1 && !isAgentCommand(args) {
		verb += " " + args[1]
	}
	n := f.n()
	switch verb {
	case "network create":
		return fmt.Appendf(nil, `{"id":"dry-net-%d","name":%q,"prefix6":"fd00:d27::/64"}`, n, args[2])
	case "service create":
		return fmt.Appendf(nil, `{"id":"dry-svc-%d","name":%q,"addr6":"fd00:d27::%x"}`, n, args[3], n)
	case "relay create", "host create", "admin create":
		return fmt.Appendf(nil, `{"id":"dry-%s","token":"dry-run"}`, args[2])
	case "relay list":
		return []byte(`[{"id":"dry-r1","name":"r1"},{"id":"dry-r2","name":"r2"},{"id":"dry-mid","name":"mid"}]`)
	case "interface list":
		return []byte(`[]`)
	case "attach":
		return fmt.Appendf(nil, `{"interface":"dry-if-%d","name":%q,"namespace":"wirenet-dry-%d","addr6":"fd00:d27::1:%x"}`, n, args[1], n, n)
	case "status":
		return []byte(`{"generation":1,"active_relays":{"dry-net":"dry-r1"}}`)
	case "interfaces":
		return []byte(`[]`)
	}
	return []byte("{}")
}

func (f *fakes) exec(argv []string) []byte {
	if len(argv) == 0 {
		return nil
	}
	switch path.Base(argv[0]) {
	case "wirenet-bench":
		if len(argv) > 1 && argv[1] == "dial" {
			// One result per namespace, as the real loop reports.
			nss := []string{""}
			for i, a := range argv {
				if a == "--netns" && i+1 < len(argv) {
					nss = strings.Split(argv[i+1], ",")
				}
			}
			var d struct {
				Results []map[string]any `json:"results"`
			}
			for _, ns := range nss {
				d.Results = append(d.Results, map[string]any{"namespace": ns, "reached": true})
			}
			b, _ := json.Marshal(d)
			return b
		}
		return []byte("{}")
	case "sh":
		if len(argv) > 2 && strings.Contains(argv[2], "wg pubkey") {
			return []byte("DRY+RUN+PUBLIC+KEY+0000000000000000000000000=\n")
		}
	case "hostbench":
		return []byte("all assertions passed\n")
	}
	return nil
}
