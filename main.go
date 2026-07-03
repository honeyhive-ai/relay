package relay

import (
	"context"
	"fmt"
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
	args := os.Args[1:]
	if len(args) > 0 {
		switch args[0] {
		case "keygen":
			fatalIf(cmdKeygen())
			return
		case "issue":
			fatalIf(cmdIssue(args[1:]))
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

	addr := resolveAddr()
	httpServer := &http.Server{Addr: addr, Handler: srv.Handler()}

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
func buildStore(ctx context.Context) (Store, error) {
	if dsn := os.Getenv("DATABASE_URL"); dsn != "" {
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

func fatalIf(err error) {
	if err != nil {
		fmt.Fprintf(os.Stderr, "hive-relay: %v\n", err)
		os.Exit(1)
	}
}
