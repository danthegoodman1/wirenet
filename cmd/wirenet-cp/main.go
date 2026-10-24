// Command wirenet-cp runs one control-plane replica: the HTTP API over a store,
// lease sweeps, and long polls for agents and relays.
package main

import (
	"context"
	"crypto/tls"
	"errors"
	"flag"
	"fmt"
	"net"
	"os"
	"os/signal"
	"strings"
	"syscall"

	"github.com/rs/zerolog"

	"github.com/danthegoodman1/wirenet/internal/cpserver"
	"github.com/danthegoodman1/wirenet/internal/store"
	"github.com/danthegoodman1/wirenet/internal/store/locked"
	"github.com/danthegoodman1/wirenet/internal/store/mem"
	"github.com/danthegoodman1/wirenet/internal/telemetry"
)

func main() {
	if err := run(); err != nil {
		fmt.Fprintln(os.Stderr, "wirenet-cp:", err)
		os.Exit(1)
	}
}

func run() error {
	cfg := cpserver.DefaultConfig("")
	listen := flag.String("listen", ":8443", "API address")
	telemetryAddr := flag.String("telemetry", ":9090", "metrics, health and pprof address")
	storeURL := flag.String("store", "memory", `"memory", or a postgres:// URL`)
	tokenFile := flag.String("admin-token-file", "", "file holding the operator's bearer token (default $WIRENET_ADMIN_TOKEN)")
	certFile := flag.String("tls-cert", "", "serve TLS with this certificate")
	keyFile := flag.String("tls-key", "", "and this key")
	logLevel := flag.String("log-level", "info", "debug, info, warn or error")
	logFormat := flag.String("log-format", "", "json or console (default: console on a terminal)")
	flag.DurationVar(&cfg.Plane.LeaseTTL, "lease-ttl", cfg.Plane.LeaseTTL, "lease term")
	flag.DurationVar(&cfg.Plane.DrainGrace, "drain-grace", cfg.Plane.DrainGrace, "how long peers keep a released interface")
	flag.DurationVar(&cfg.Plane.Quarantine4, "quarantine4", cfg.Plane.Quarantine4, "how long an IPv4 address waits for reuse once its interface drains")
	flag.DurationVar(&cfg.Plane.PortQuarantine, "port-quarantine", cfg.Plane.PortQuarantine, "how long a released relay port waits")
	flag.DurationVar(&cfg.Plane.Retention, "retention", cfg.Plane.Retention, "how long an ended interface stays visible to its host")
	flag.IntVar(&cfg.Plane.MTU, "mtu", cfg.Plane.MTU, "overlay MTU for networks that name none")
	flag.DurationVar(&cfg.PollTimeout, "poll-timeout", cfg.PollTimeout, "how long a long poll parks")
	flag.DurationVar(&cfg.CensusEvery, "census-every", cfg.CensusEvery, "how often to count interfaces, IPv4 quarantine and relay ports for metrics")
	flag.IntVar(&cfg.Plane.Quota.Interfaces, "quota-interfaces", 0, "the most live interfaces a network holds unless it names a quota; 0 for no bound")
	flag.IntVar(&cfg.Plane.Quota.Services, "quota-services", 0, "the most services a network holds unless it names a quota; 0 for no bound")
	flag.IntVar(&cfg.Plane.Quota.Rules, "quota-rules", 0, "the most rules a network holds unless it names a quota; 0 for no bound")
	flag.IntVar(&cfg.Plane.Quota.Edges, "quota-edges", 0, "the most edges a network holds unless it names a quota; 0 for no bound")
	flag.Float64Var(&cfg.Limits.Rate, "scoped-rate", cfg.Limits.Rate, "writes a second each scoped host or admin token may make on this replica; 0 for no bound")
	flag.IntVar(&cfg.Limits.Burst, "scoped-burst", cfg.Limits.Burst, "writes a scoped host or admin token may make at once")
	flag.IntVar(&cfg.Limits.InFlight, "scoped-in-flight", cfg.Limits.InFlight, "calls a scoped host or admin token may have running on this replica, long polls included; 0 for no bound")
	flag.Parse()

	log, err := telemetry.NewLogger("cp", telemetry.LogConfig{Level: *logLevel, Format: *logFormat})
	if err != nil {
		return err
	}
	cfg.AdminToken = os.Getenv("WIRENET_ADMIN_TOKEN")
	if *tokenFile != "" {
		b, err := os.ReadFile(*tokenFile)
		if err != nil {
			return err
		}
		cfg.AdminToken = strings.TrimSpace(string(b))
	}
	ctx, stop := signal.NotifyContext(context.Background(), syscall.SIGINT, syscall.SIGTERM)
	defer stop()

	st, closeStore, err := openStore(ctx, *storeURL, log)
	if err != nil {
		return err
	}
	defer closeStore()
	reg := telemetry.NewRegistry()
	srv, err := cpserver.New(cfg, st, log, reg)
	if err != nil {
		return err
	}
	ln, err := net.Listen("tcp", *listen)
	if err != nil {
		return err
	}
	if *certFile != "" {
		cert, err := tls.LoadX509KeyPair(*certFile, *keyFile)
		if err != nil {
			return err
		}
		ln = tls.NewListener(ln, &tls.Config{Certificates: []tls.Certificate{cert}, MinVersion: tls.VersionTLS12})
	}
	tel := &telemetry.Server{Addr: *telemetryAddr, Registry: reg, Log: log}
	errs := make(chan error, 3)
	go func() { errs <- tel.Serve(ctx) }()
	go func() { errs <- srv.Run(ctx) }()
	go func() { errs <- srv.Serve(ctx, ln) }()
	select {
	case <-ctx.Done():
		log.Info().Msg("shutting down")
		return nil
	case err := <-errs:
		return err
	}
}

func openStore(ctx context.Context, url string, log zerolog.Logger) (store.Store, func(), error) {
	switch {
	case url == "memory":
		log.Warn().Msg("using the in-memory store: everything is lost on exit")
		return locked.New(mem.New()), func() {}, nil
	case strings.HasPrefix(url, "postgres://"), strings.HasPrefix(url, "postgresql://"):
		return openPostgres(ctx, url, log)
	}
	return nil, nil, errors.New(`store must be "memory" or a postgres:// URL`)
}
