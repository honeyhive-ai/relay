package relay

import (
	"context"
	"fmt"
	"log/slog"
	"net/http"
	"os"
	"os/signal"
	"strconv"
	"syscall"
	"time"
)

// hive-relay — the rendezvous + envelope-forwarding server.
//
// Address resolution (cloud-friendly), most specific first:
//  1. $PORT (set by Fly / Cloud Run / Railway / Heroku) → 0.0.0.0:$PORT
//  2. $HIVE_RELAY_ADDR (full host:port)
//  3. default 0.0.0.0:8443
//
// Storage:
//   - $DATABASE_URL set        → shared Postgres store (HA; no data migration).
//   - else $HIVE_RELAY_DATA_DIR → in-memory + JSON snapshot (single instance).
//   - else                      → in-memory only (ephemeral; tests).
//
// $HIVE_RELAY_FRIEND_CAP (optional) caps accepted friends per account.

func Main() {
	// Structured JSON logs (request lines come from the observability middleware).
	slog.SetDefault(slog.New(slog.NewJSONHandler(os.Stderr, &slog.HandlerOptions{Level: slog.LevelInfo})))

	args := os.Args[1:]
	if len(args) > 0 {
		switch args[0] {
		case "keygen":
			fatalIf(cmdKeygen())
			return
		case "issue":
			fatalIf(cmdIssue(args[1:]))
			return
		case "bootstrap-agent":
			fatalIf(cmdBootstrapAgent(args[1:]))
			return
		case "help", "--help", "-h":
			printUsage()
			return
		}
	}

	store, err := buildStore(context.Background())
	fatalIf(err)
	defer store.Close()

	// Open relay: default env entitlement, no write guard, no hooks. (The
	// downstream binary can build its own Server via relay.New with custom seams.)
	srv := New(Options{Store: store, FriendCap: friendCapFromEnv()})

	// Periodically snapshot durable state so an unexpected crash loses at most a
	// few seconds; a graceful shutdown flushes once more below.
	stopFlush := make(chan struct{})
	if store.PersistenceEnabled() {
		go flushLoop(store, stopFlush)
	}

	// Bound envelope growth on backends that don't prune inline (Postgres). The
	// in-memory store already enforces the same caps at write time.
	if pruner, ok := store.(envelopePruner); ok {
		go pruneLoop(pruner, stopFlush)
	}

	addr := resolveAddr()
	// Timeouts bound how long a single connection can tie up resources, which
	// defends against Slowloris (trickled headers/body) and stuck peers. The
	// relay is poll-based, not long-lived streaming, so modest read/write
	// deadlines are safe.
	httpServer := &http.Server{
		Addr:              addr,
		Handler:           srv.Handler(),
		ReadHeaderTimeout: 10 * time.Second,
		ReadTimeout:       30 * time.Second,
		WriteTimeout:      30 * time.Second,
		IdleTimeout:       120 * time.Second,
	}

	// Stop on Ctrl-C or SIGTERM (a redeploy from the orchestrator).
	ctx, stop := signal.NotifyContext(context.Background(), os.Interrupt, syscall.SIGTERM)
	defer stop()

	go func() {
		fmt.Printf("hive-relay listening on %s\n", addr)
		if err := httpServer.ListenAndServe(); err != nil && err != http.ErrServerClosed {
			fmt.Fprintf(os.Stderr, "hive-relay: serve error: %v\n", err)
			stop()
		}
	}()

	<-ctx.Done()
	close(stopFlush)

	shutCtx, cancel := context.WithTimeout(context.Background(), 10*time.Second)
	defer cancel()
	_ = httpServer.Shutdown(shutCtx)

	// Final flush on the way out so a planned redeploy never loses state.
	if err := store.Flush(context.Background()); err != nil {
		fmt.Fprintf(os.Stderr, "hive-relay: final flush failed: %v\n", err)
	}
}

// buildStore selects the storage backend from the environment.
//
// The public production relay sets HIVE_RELAY_REQUIRE_DB=1 so it REFUSES to boot
// on the ephemeral in-memory fallback: a missing/typo'd DATABASE_URL there would
// otherwise silently serve every client from volatile memory and lose state on
// the next machine move (P2-16). Self-hosters leave it unset and keep the
// snapshot-store fallback.
func buildStore(ctx context.Context) (Store, error) {
	dsn := os.Getenv("DATABASE_URL")
	if envBool("HIVE_RELAY_REQUIRE_DB") && dsn == "" {
		return nil, fmt.Errorf("HIVE_RELAY_REQUIRE_DB is set but DATABASE_URL is empty: refusing to boot on the ephemeral in-memory store")
	}
	if dsn != "" {
		return newPostgresStore(ctx, dsn)
	}
	if dir := os.Getenv("HIVE_RELAY_DATA_DIR"); dir != "" {
		return newMemoryStoreWithPersistence(dir), nil
	}
	return newMemoryStore(), nil
}

func resolveAddr() string {
	if port := os.Getenv("PORT"); port != "" {
		return "0.0.0.0:" + port
	}
	if addr := os.Getenv("HIVE_RELAY_ADDR"); addr != "" {
		return addr
	}
	return "0.0.0.0:8443"
}

func friendCapFromEnv() *int {
	if v := os.Getenv("HIVE_RELAY_FRIEND_CAP"); v != "" {
		if n, err := strconv.Atoi(v); err == nil {
			return &n
		}
	}
	return nil
}

func flushLoop(store Store, stop <-chan struct{}) {
	tick := time.NewTicker(5 * time.Second)
	defer tick.Stop()
	for {
		select {
		case <-stop:
			return
		case <-tick.C:
			if err := store.Flush(context.Background()); err != nil {
				fmt.Fprintf(os.Stderr, "hive-relay: snapshot flush failed: %v\n", err)
			}
		}
	}
}

// envelopePruner is implemented by backends whose durable logs need periodic
// pruning (Postgres). The in-memory store prunes inline at write time instead.
// Beyond envelopes, the loop also sweeps the inbox, keyring, and terminal friend
// requests so no durable table grows without bound (P2-13).
type envelopePruner interface {
	PruneEnvelopes(ctx context.Context, maxEnvelopes int, maxAge time.Duration) (int64, error)
	PruneInbox(ctx context.Context, maxRows int, maxAge time.Duration) (int64, error)
	PruneKeyring(ctx context.Context, maxPerWorkspace int) (int64, error)
	PruneFriendRequests(ctx context.Context, maxAge time.Duration) (int64, error)
}

func pruneLoop(pruner envelopePruner, stop <-chan struct{}) {
	maxEnv, maxAge := retentionFromEnv()
	inboxAge := daysEnv("HIVE_RELAY_INBOX_RETENTION_DAYS", defaultInboxMaxAgeDays)
	friendReqAge := daysEnv("HIVE_RELAY_FRIEND_REQ_RETENTION_DAYS", defaultFriendReqMaxAgeDays)
	tick := time.NewTicker(time.Hour)
	defer tick.Stop()
	for {
		select {
		case <-stop:
			return
		case <-tick.C:
			runPrune("envelopes", func() (int64, error) {
				return pruner.PruneEnvelopes(context.Background(), maxEnv, maxAge)
			})
			runPrune("inbox", func() (int64, error) {
				return pruner.PruneInbox(context.Background(), defaultInboxMaxRows, inboxAge)
			})
			runPrune("keyring", func() (int64, error) {
				return pruner.PruneKeyring(context.Background(), defaultMaxKeyringPerWS)
			})
			runPrune("friend_requests", func() (int64, error) {
				return pruner.PruneFriendRequests(context.Background(), friendReqAge)
			})
		}
	}
}

// runPrune executes one prune step and logs the outcome.
func runPrune(what string, fn func() (int64, error)) {
	n, err := fn()
	if err != nil {
		slog.Warn("prune failed", "table", what, "error", err)
	} else if n > 0 {
		slog.Info("pruned rows", "table", what, "deleted", n)
	}
}

// daysEnv reads a non-negative day count from env, else the default (0 disables).
func daysEnv(name string, def int) time.Duration {
	d := def
	if v := os.Getenv(name); v != "" {
		if n, err := strconv.Atoi(v); err == nil && n >= 0 {
			d = n
		}
	}
	return time.Duration(d) * 24 * time.Hour
}

func fatalIf(err error) {
	if err != nil {
		fmt.Fprintf(os.Stderr, "hive-relay: %v\n", err)
		os.Exit(1)
	}
}
