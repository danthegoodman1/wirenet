package main

import (
	"bytes"
	"context"
	"errors"
	"fmt"
	"io"
	"net/netip"
	"os/exec"
	"strings"
	"sync"
)

// Role is what a node does in the fleet.
type Role string

const (
	RoleCP    Role = "cp"
	RoleAgent Role = "agent"
	RoleRelay Role = "relay"
	// RoleMiddle plays both middle-box roles of the path comparison: a
	// relay, and a WireGuard-terminating gateway.
	RoleMiddle Role = "middle"
)

// Node is one machine of the fleet, or the namespace standing in for one.
type Node struct {
	Name string
	Role Role
	// Addr is the underlay address other nodes reach it at.
	Addr netip.Addr
}

// Stopper ends a process an environment started.
type Stopper interface {
	Stop(ctx context.Context) error
}

// Env is a fleet a plan runs against: namespaces on this machine, or
// instances on EC2. Every method that runs something reports failure,
// including a remote command's exit status.
type Env interface {
	Name() string
	// DryRun reports whether commands are printed rather than run.
	DryRun() bool
	// Up purges what an earlier run left, then, when fleet is set, starts
	// a fresh control plane, relays and agents.
	Up(ctx context.Context, fleet bool) error
	// Down stops the fleet and purges what the run left.
	Down(ctx context.Context) error
	CP() Node
	Hosts() []Node
	// Relays are the relays a network's set draws from, the middle box
	// excluded.
	Relays() []Node
	Middle() Node
	// Exec runs argv as root on n, in the node's own namespace, and
	// returns its stdout.
	Exec(ctx context.Context, n Node, argv ...string) ([]byte, error)
	// Spawn starts argv as root on n in the background.
	Spawn(ctx context.Context, n Node, argv ...string) (Stopper, error)
	// Ctl runs wirenetctl: agent commands (attach, detach, interfaces,
	// status) against n's agent, and the rest against the control plane.
	Ctl(ctx context.Context, n Node, args ...string) ([]byte, error)
	// OperatorAPI is how a command run on the control-plane node reaches
	// the API as the operator: its URL there, and the wirenet-bench flags
	// that give it the operator's token, which stays on that node.
	OperatorAPI() (url string, tokenArgs []string)
	// Bin is the path of one of the fleet's binaries on a node.
	Bin(name string) string
	// AgentSocket is the path of n's agent socket.
	AgentSocket(n Node) string
	// NamespacePrefix starts the name of every namespace n's agent makes.
	NamespacePrefix(n Node) string
	// ScratchNS names a namespace a plan may create on n; Down removes it.
	ScratchNS(n Node) string
	// Metrics returns a daemon's metrics text.
	Metrics(ctx context.Context, n Node) (string, error)
	// StopRelay kills a relay as a crash does, and keeps it down.
	StopRelay(ctx context.Context, n Node) error
	// StartRelay starts a stopped relay and waits until it is ready.
	StartRelay(ctx context.Context, n Node) error
	Substrate(ctx context.Context) (Substrate, error)
}

// localOptions configure the local environment.
type localOptions struct {
	bin, store, logLevel, keep string
	hosts                      int
	log                        io.Writer
}

// Substrate is what produced a report's numbers.
type Substrate struct {
	Env    string `json:"env"`
	Region string `json:"region"`
	// InstanceTypes is by role, or "local".
	InstanceTypes map[Role]string `json:"instance_types"`
	// Store is the control plane's store.
	Store string    `json:"store"`
	Nodes []Machine `json:"nodes"`
}

// Machine describes one machine's kernel and CPUs.
type Machine struct {
	Nodes   []string `json:"nodes"`
	Kernel  string   `json:"kernel"`
	CPU     string   `json:"cpu"`
	CPUs    string   `json:"cpus"`
	RmemMax string   `json:"rmem_max"`
}

// probeScript prints what Machine records, one value per line.
const probeScript = `uname -r; grep -m1 'model name' /proc/cpuinfo | cut -d: -f2-; nproc; cat /proc/sys/net/core/rmem_max`

func parseMachine(node string, out []byte) Machine {
	lines := strings.Split(strings.TrimSpace(string(out)), "\n")
	for len(lines) < 4 {
		lines = append(lines, "")
	}
	return Machine{Nodes: []string{node}, Kernel: lines[0], CPU: strings.TrimSpace(lines[1]), CPUs: lines[2], RmemMax: lines[3]}
}

// isAgentCommand reports whether wirenetctl serves args from the local agent.
func isAgentCommand(args []string) bool {
	if len(args) == 0 {
		return false
	}
	switch args[0] {
	case "attach", "detach", "interfaces", "status":
		return true
	}
	return false
}

// shellQuote quotes s for a POSIX shell.
func shellQuote(s string) string {
	if s != "" && strings.Trim(s, "abcdefghijklmnopqrstuvwxyzABCDEFGHIJKLMNOPQRSTUVWXYZ0123456789-_./:=,@%+") == "" {
		return s
	}
	return "'" + strings.ReplaceAll(s, "'", `'\''`) + "'"
}

func shellJoin(argv []string) string {
	q := make([]string, len(argv))
	for i, a := range argv {
		q[i] = shellQuote(a)
	}
	return strings.Join(q, " ")
}

// output runs cmd and returns its stdout, folding stderr into the error.
func output(cmd *exec.Cmd, where string) ([]byte, error) {
	var stdout, stderr bytes.Buffer
	cmd.Stdout, cmd.Stderr = &stdout, &stderr
	if err := cmd.Run(); err != nil {
		return stdout.Bytes(), fmt.Errorf("%s: %s: %v: %s", where, strings.Join(cmd.Args, " "), err, strings.TrimSpace(stderr.String()))
	}
	return stdout.Bytes(), nil
}

// forEach runs fn on every node at once and joins their errors.
func forEach(nodes []Node, fn func(Node) error) error {
	errs := make([]error, len(nodes))
	var wg sync.WaitGroup
	for i, n := range nodes {
		wg.Go(func() { errs[i] = fn(n) })
	}
	wg.Wait()
	return errors.Join(errs...)
}
