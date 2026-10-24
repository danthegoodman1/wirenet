package pgstore_test

import (
	"context"
	"fmt"
	"os"
	"slices"
	"strings"
	"testing"
	"time"

	"github.com/jackc/pgx/v5"

	"github.com/danthegoodman1/wirenet/internal/api"
	"github.com/danthegoodman1/wirenet/internal/model"
	"github.com/danthegoodman1/wirenet/internal/store"
	"github.com/danthegoodman1/wirenet/internal/store/pgstore"
	"github.com/danthegoodman1/wirenet/internal/store/pgstore/pgtest"
	"github.com/danthegoodman1/wirenet/internal/store/storetest"
)

func TestConformance(t *testing.T) {
	pgtest.DSN(t)
	storetest.Run(t, func(t *testing.T) store.Store { return pgtest.Open(t) })
}

func TestOpenAppliesMigrationsOnce(t *testing.T) {
	dsn := pgtest.NewSchema(t)
	setMeta(t, pgtest.OpenDSN(t, dsn), "v")
	// The schema is current, so opening again applies nothing and keeps
	// what is stored.
	if v := getMeta(t, pgtest.OpenDSN(t, dsn)); v != "v" {
		t.Fatalf("meta %q after reopening", v)
	}
}

func setMeta(t *testing.T, s store.Store, v string) {
	t.Helper()
	if _, err := s.Update(t.Context(), func(tx store.Tx) error { return tx.SetMeta("k", v) }); err != nil {
		t.Fatal(err)
	}
}

func getMeta(t *testing.T, s store.Store) string {
	t.Helper()
	var v string
	if err := s.View(t.Context(), func(tx store.ReadTx) error {
		var err error
		v, _, err = tx.Meta("k")
		return err
	}); err != nil {
		t.Fatal(err)
	}
	return v
}

// TestUpdateRetriesASerializationFailure commits a write to what a
// transaction read, between its read and its own write, and checks that
// Update runs fn again, whether fn returns the failure or drops it.
func TestUpdateRetriesASerializationFailure(t *testing.T) {
	for _, drop := range []bool{false, true} {
		t.Run(fmt.Sprintf("drop=%v", drop), func(t *testing.T) {
			s := pgtest.Open(t)
			setMeta(t, s, "0")
			attempts := 0
			_, err := s.Update(t.Context(), func(tx store.Tx) error {
				attempts++
				v, _, err := tx.Meta("k")
				if err != nil {
					return err
				}
				if attempts == 1 {
					setMeta(t, s, "other")
				}
				err = tx.SetMeta("k", v+"+1")
				if drop {
					return nil
				}
				return err
			})
			if err != nil {
				t.Fatal(err)
			}
			if v := getMeta(t, s); attempts != 2 || v != "other+1" {
				t.Fatalf("%d attempts left %q, want 2 leaving other+1", attempts, v)
			}
		})
	}
}

// TestUpdateRefusesToCommitPastAFailedStatement drops a statement's error
// and returns nil; Postgres aborted the transaction, so Update fails.
func TestUpdateRefusesToCommitPastAFailedStatement(t *testing.T) {
	s := pgtest.Open(t)
	_, err := s.Update(t.Context(), func(tx store.Tx) error {
		// The released address is the key, and a zero one is NULL.
		_ = tx.PutReleased4(store.Released4{Network: "net-a"})
		return tx.SetMeta("k", "v")
	})
	if err == nil {
		t.Fatal("committed past a failed statement")
	}
	if v := getMeta(t, s); v != "" {
		t.Fatalf("meta %q after a failed update", v)
	}
}

// receive reads changes until one passes keep, or fails t after a while.
// Every test database shares the notification channel, so a test keeps only
// the changes it made.
func receive(t *testing.T, ch <-chan store.Change, keep func(store.Change) bool) store.Change {
	t.Helper()
	timeout := time.After(10 * time.Second)
	for {
		select {
		case c, ok := <-ch:
			if !ok {
				t.Fatal("watch closed")
			}
			if keep(c) {
				return c
			}
		case <-timeout:
			t.Fatal("no change arrived")
		}
	}
}

func touching(prefix string) func(store.Change) bool {
	return func(c store.Change) bool {
		return slices.ContainsFunc(c.Networks, func(id model.NetworkID) bool { return strings.HasPrefix(string(id), prefix) }) ||
			slices.ContainsFunc(c.Hosts, func(id model.HostID) bool { return strings.HasPrefix(string(id), prefix) })
	}
}

func TestWatchDeliversCommittedChanges(t *testing.T) {
	s := pgtest.Open(t)
	ctx, cancel := context.WithCancel(t.Context())
	watch, err := s.Watch(ctx)
	if err != nil {
		t.Fatal(err)
	}
	prefix := fmt.Sprintf("net-watch%d-", time.Now().UnixNano())
	id := model.NetworkID(prefix + "a")

	// A failed transaction announces nothing; the next commit is the first
	// change to arrive.
	if _, err := s.Update(t.Context(), func(tx store.Tx) error {
		tx.Touch(store.Change{Networks: []model.NetworkID{model.NetworkID(prefix + "failed")}})
		return fmt.Errorf("fail")
	}); err == nil {
		t.Fatal("a failing update committed")
	}
	// Garbage on the channel is dropped.
	notify(t, "not json")
	want, err := s.Update(t.Context(), func(tx store.Tx) error {
		tx.Touch(store.Change{Networks: []model.NetworkID{id}})
		_, err := tx.Bump()
		return err
	})
	if err != nil {
		t.Fatal(err)
	}
	got := receive(t, watch, touching(prefix))
	if got.Revision != want.Revision || !slices.Equal(got.Networks, want.Networks) {
		t.Fatalf("watched %+v, committed %+v", got, want)
	}

	cancel()
	deadline := time.After(10 * time.Second)
	for open := true; open; {
		select {
		case _, open = <-watch:
		case <-deadline:
			t.Fatal("watch stayed open after its context ended")
		}
	}
}

// TestWatchSplitsLargeChanges commits a change too large for one
// notification and checks that its parts together name every host.
func TestWatchSplitsLargeChanges(t *testing.T) {
	s := pgtest.Open(t)
	watch, err := s.Watch(t.Context())
	if err != nil {
		t.Fatal(err)
	}
	prefix := fmt.Sprintf("host-split%d-", time.Now().UnixNano())
	var hosts []model.HostID
	for i := range 1000 {
		hosts = append(hosts, model.HostID(fmt.Sprintf("%s%04d", prefix, i)))
	}
	want, err := s.Update(t.Context(), func(tx store.Tx) error {
		tx.Touch(store.Change{Hosts: hosts})
		_, err := tx.Bump()
		return err
	})
	if err != nil {
		t.Fatal(err)
	}
	var got store.Change
	parts := 0
	for len(got.Hosts) < len(hosts) {
		c := receive(t, watch, touching(prefix))
		if c.Revision != want.Revision {
			t.Fatalf("part carries revision %d, want %d", c.Revision, want.Revision)
		}
		got.Merge(c)
		parts++
	}
	if parts < 2 || !slices.Equal(got.Hosts, want.Hosts) {
		t.Fatalf("%d parts naming %d hosts, want several naming %d", parts, len(got.Hosts), len(want.Hosts))
	}
}

// notify sends a raw notification from a connection of its own.
func notify(t *testing.T, payload string) {
	t.Helper()
	conn, err := pgx.Connect(t.Context(), pgtest.DSN(t))
	if err != nil {
		t.Fatal(err)
	}
	defer func() {
		if err := conn.Close(t.Context()); err != nil {
			t.Error(err)
		}
	}()
	if _, err := conn.Exec(t.Context(), "SELECT pg_notify($1, $2)", pgstore.Channel, payload); err != nil {
		t.Fatal(err)
	}
}

// TestScopesMigrationKeepsEarlierHostsGlobal builds a schema at 0006 with a
// host and a network written before scopes existed, then opens it, which
// applies 0007: the host stays global and the network bounds nothing.
func TestScopesMigrationKeepsEarlierHostsGlobal(t *testing.T) {
	dsn := pgtest.NewSchema(t)
	ctx := t.Context()
	conn, err := pgx.Connect(ctx, dsn)
	if err != nil {
		t.Fatal(err)
	}
	stmts := []string{`CREATE TABLE schema_migrations (
		version text COLLATE "C" PRIMARY KEY,
		applied timestamptz NOT NULL DEFAULT now()
	)`}
	for _, v := range []string{"0001_init", "0002_network_changed", "0003_rule_deny", "0004_edge_epoch", "0005_drop_edge_epoch", "0006_interface_member"} {
		b, err := os.ReadFile("schema/" + v + ".sql")
		if err != nil {
			t.Fatal(err)
		}
		stmts = append(stmts, string(b), fmt.Sprintf("INSERT INTO schema_migrations (version) VALUES ('%s')", v))
	}
	stmts = append(stmts,
		`INSERT INTO hosts (id, name, token_hash, endpoint, revision, created)
		VALUES ('host-old', 'old', decode(repeat('07', 32), 'hex'), '', 1, now())`,
		`INSERT INTO networks (id, name, mtu, relays, next6, next4, revision, created, changed)
		VALUES ('net-old', 'old', 1380, '[]', 256, 1, 1, now(), now())`,
	)
	for _, sql := range stmts {
		if _, err := conn.Exec(ctx, sql); err != nil {
			t.Fatalf("%.60s: %v", sql, err)
		}
	}
	if err := conn.Close(ctx); err != nil {
		t.Fatal(err)
	}
	s := pgtest.OpenDSN(t, dsn)
	if err := s.View(ctx, func(tx store.ReadTx) error {
		h, err := tx.Host("host-old")
		if err != nil {
			return err
		}
		if !h.Scope.Global || h.Scope.Networks != nil {
			t.Errorf("an earlier host's scope is %+v, want global", h.Scope)
		}
		n, err := tx.Network("net-old")
		if err != nil {
			return err
		}
		if n.Quota != (api.Quota{}) {
			t.Errorf("an earlier network's quota is %+v, want none", n.Quota)
		}
		return nil
	}); err != nil {
		t.Fatal(err)
	}
}
