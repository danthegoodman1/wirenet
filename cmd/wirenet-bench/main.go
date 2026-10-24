//go:build linux

// Command wirenet-bench measures a path between two namespaces or hosts, and
// drives a host agent's local API under load. It uses the standard library
// alone, so one binary copied to a host is the whole install. Every
// subcommand prints one JSON object on stdout; the types are in
// internal/bench.
//
//	wirenet-bench serve  [--listen ADDR:PORT,...] [--netns NS] [--name NAME]
//	wirenet-bench stream --target ADDR:PORT [--duration 10s] [--parallel 1] [--reverse] [--netns NS]
//	wirenet-bench rr     --target ADDR:PORT [--size 1] [--duration 5s | --count N] [--interval 0] [--netns NS]
//	wirenet-bench dial   --target ADDR:PORT [--netns NS,NS,...] [--want NAME] [--streak 1] [--until 10s]
//	wirenet-bench lookup --name NAME --want ADDR | --unlike ADDR [--netns NS] [--until 10s]
//	wirenet-bench cpu    [--duration 10s]
//	wirenet-bench api    --cp URL --token T | --token-file F --network NET [--hidden NET] [--rounds 20 | --duration D] [--port 20000]
//	wirenet-bench agent attach  --network NET --service SVC --name NAME [--rounds 1] [--dial ADDR:PORT] [--detach] [--member M [--replace]]
//	wirenet-bench agent detach  --interface ID
//	wirenet-bench agent churn   --network NET --service SVC --name PREFIX [--duration 10s] [--concurrency 4]
//	wirenet-bench agent density --network NET --service SVC --name PREFIX [--max 1000] [--dial ADDR:PORT]
//
// --netns names a namespace under /run/netns, or a path; sockets are opened
// inside it. A --target may name a host, which the namespace's resolver,
// the agent's at 127.0.0.53, resolves for each connection. The agent
// subcommands take --socket, the agent's local API.
package main

import (
	"encoding/json"
	"errors"
	"flag"
	"fmt"
	"os"
	"runtime"
	"strings"
	"syscall"
	"time"
)

func main() {
	if err := run(os.Args[1:]); err != nil {
		fmt.Fprintln(os.Stderr, "wirenet-bench:", err)
		os.Exit(1)
	}
}

func run(args []string) error {
	if len(args) == 0 {
		return errors.New("usage: wirenet-bench serve|stream|rr|dial|lookup|cpu|api|agent ...; see the package documentation")
	}
	cmds := map[string]func([]string) error{
		"serve": serve, "stream": stream, "rr": rr, "dial": dial, "lookup": lookup, "cpu": cpu, "api": api, "agent": agent,
	}
	cmd, ok := cmds[args[0]]
	if !ok {
		return fmt.Errorf("unknown subcommand %q", args[0])
	}
	return cmd(args[1:])
}

func emit(v any) error {
	enc := json.NewEncoder(os.Stdout)
	return enc.Encode(v)
}

// parse parses flags and rejects positional arguments.
func parse(fs *flag.FlagSet, args []string) error {
	if err := fs.Parse(args); err != nil {
		return err
	}
	if fs.NArg() > 0 {
		return fmt.Errorf("%s: unexpected arguments %q", fs.Name(), fs.Args())
	}
	return nil
}

// startAt waits until the wall-clock time at names, RFC 3339, so runs on
// several machines share one window; an empty at starts now. A run that is
// ready only after its start fails, since its window would no longer match
// the others'.
func startAt(at string) error {
	if at == "" {
		return nil
	}
	t, err := time.Parse(time.RFC3339Nano, at)
	if err != nil {
		return fmt.Errorf("--at: %w", err)
	}
	wait := time.Until(t)
	if wait < 0 {
		return fmt.Errorf("ready %v after the start at %s", -wait, at)
	}
	time.Sleep(wait)
	return nil
}

// inNetns runs fn on a thread inside a network namespace, so sockets fn
// opens belong to it. An empty name runs fn where the process is.
func inNetns(name string, fn func() error) error {
	if name == "" {
		return fn()
	}
	path := name
	if !strings.Contains(name, "/") {
		path = "/run/netns/" + name
	}
	runtime.LockOSThread()
	defer runtime.UnlockOSThread()
	self, err := os.Open("/proc/thread-self/ns/net")
	if err != nil {
		return err
	}
	defer self.Close()
	target, err := os.Open(path)
	if err != nil {
		return err
	}
	defer target.Close()
	if err := setns(target.Fd()); err != nil {
		return fmt.Errorf("entering %s: %w", path, err)
	}
	ferr := fn()
	if err := setns(self.Fd()); err != nil {
		// Lock once more so the deferred unlock leaves the thread locked:
		// it then dies with its goroutine instead of carrying the wrong
		// namespace back to the scheduler.
		runtime.LockOSThread()
		return errors.Join(ferr, fmt.Errorf("leaving %s: %w", path, err))
	}
	return ferr
}

func setns(fd uintptr) error {
	if _, _, e := syscall.Syscall(sysSetns, fd, syscall.CLONE_NEWNET, 0); e != 0 {
		return e
	}
	return nil
}
