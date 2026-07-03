package relay

import (
	"context"
	"os"
	"testing"

	"github.com/jackc/pgx/v5/pgxpool"
)

// Postgres integration tests run only when TEST_DATABASE_URL points at a
// disposable database (CI / local docker). Each test truncates the relay tables
// first for isolation.
//
//	docker run --rm -e POSTGRES_PASSWORD=relay -e POSTGRES_DB=relay -p 55432:5432 postgres:16-alpine
//	TEST_DATABASE_URL=postgres://postgres:relay@127.0.0.1:55432/relay go test ./...

func pgStore(t *testing.T) *postgresStore {
	t.Helper()
	dsn := os.Getenv("TEST_DATABASE_URL")
	if dsn == "" {
		t.Skip("set TEST_DATABASE_URL to run Postgres integration tests")
	}
	st, err := newPostgresStore(context.Background(), dsn)
	if err != nil {
		t.Fatalf("connect: %v", err)
	}
	t.Cleanup(func() { st.Close() })
	ps := st.(*postgresStore)
	// Isolate each test.
	if _, err := ps.pool.Exec(bg, `TRUNCATE relay_seq, relay_envelopes, relay_candidates,
		relay_presence, relay_keyring, relay_directory, relay_directory_devices, relay_accounts,
		relay_account_devices, relay_login_index, relay_inbox, relay_friend_requests, relay_friend_edges`); err != nil {
		t.Fatalf("truncate: %v", err)
	}
	return ps
}

func TestPG_EnvelopeSeqMonotonicAndCursor(t *testing.T) {
	s := pgStore(t)
	for want := uint64(1); want <= 3; want++ {
		got, err := s.AppendEnvelope(bg, "ws1", raw(`{"ct":"x"}`))
		if err != nil || got != want {
			t.Fatalf("append: got %d want %d err %v", got, want, err)
		}
	}
	rows, _ := s.EnvelopesAfter(bg, "ws1", 1)
	if len(rows) != 2 || rows[0].Seq != 2 || rows[1].Seq != 3 {
		t.Fatalf("after=1: %+v", rows)
	}
	// Distinct workspace has its own sequence.
	if got, _ := s.AppendEnvelope(bg, "ws2", raw(`{}`)); got != 1 {
		t.Fatalf("ws2 seq should restart at 1, got %d", got)
	}
}

func TestPG_AccountInboxAndDevices(t *testing.T) {
	s := pgStore(t)
	key, _ := s.RegisterAccountDevice(bg, 42, "Octocat", "devA", strptr("nodeA"), nil, 100)
	_, _ = s.RegisterAccountDevice(bg, 42, "octocat", "devB", nil, nil, 101)
	if devs, _ := s.AccountDevices(bg, key); len(devs) != 2 {
		t.Fatalf("devices: %d", len(devs))
	}
	if k, ok, _ := s.AccountKeyForLogin(bg, "@OCTOCAT"); !ok || k != key {
		t.Fatalf("login index: %q %v", k, ok)
	}
	if seq, _ := s.PushAccountEvent(bg, key, raw(`{"kind":"ping"}`)); seq != 1 {
		t.Fatalf("inbox seq %d", seq)
	}
	if rows, _ := s.AccountInboxAfter(bg, key, 0); len(rows) != 1 {
		t.Fatalf("inbox: %+v", rows)
	}
	if rows, _ := s.AccountInboxAfter(bg, key, 1); len(rows) != 0 {
		t.Fatal("cursor should exhaust inbox")
	}
	// Heartbeat only succeeds for a registered device.
	if ok, _ := s.HeartbeatDevice(bg, 42, "ghost", 200); ok {
		t.Fatal("ghost heartbeat should fail")
	}
	if ok, _ := s.HeartbeatDevice(bg, 42, "devA", 200); !ok {
		t.Fatal("devA heartbeat should succeed")
	}
}

func TestPG_FriendLifecycleAndPresence(t *testing.T) {
	s := pgStore(t)
	_, _ = s.RegisterAccountDevice(bg, 1, "alice", "d1", nil, nil, 0)
	_, _ = s.RegisterAccountDevice(bg, 2, "bob", "d2", strptr("node-b"), nil, 0)
	a, b := accountKey(1), accountKey(2)

	req, err := s.CreateFriendRequest(bg, a, "alice", b, "bob", 10, nil)
	if err != nil {
		t.Fatal(err)
	}
	// Idempotent duplicate.
	if dup, _ := s.CreateFriendRequest(bg, a, "alice", b, "bob", 10, nil); dup.ID != req.ID {
		t.Fatal("duplicate pending should be idempotent")
	}
	// Strangers can't see devices.
	if _, ok, _ := s.FriendDevices(bg, a, b); ok {
		t.Fatal("strangers should not see devices")
	}
	if _, err := s.AcceptFriendRequest(bg, req.ID, b, nil); err != nil {
		t.Fatal(err)
	}
	if f, _ := s.AreFriends(bg, a, b); !f {
		t.Fatal("should be friends")
	}
	if n, _ := s.FriendCount(bg, a); n != 1 {
		t.Fatalf("count %d", n)
	}
	if friends, _ := s.ListFriends(bg, a); len(friends) != 1 || friends[0].Login != "bob" {
		t.Fatalf("list: %+v", friends)
	}
	rows, ok, _ := s.FriendDevices(bg, a, b)
	if !ok || len(rows) != 1 || rows[0].NodeID == nil || *rows[0].NodeID != "node-b" {
		t.Fatalf("friend devices: ok=%v %+v", ok, rows)
	}

	// Presence: bob online after heartbeat, offline when appearing offline.
	_, _ = s.HeartbeatDevice(bg, 2, "d2", 1000)
	if pres, _ := s.FriendPresence(bg, a, 1010); len(pres) != 1 || pres[0].Presence != "online" {
		t.Fatalf("presence: %+v", pres)
	}
	_ = s.SetVisibility(bg, 2, true)
	if pres, _ := s.FriendPresence(bg, a, 1010); pres[0].Presence != "offline" {
		t.Fatalf("appear-offline: %+v", pres)
	}

	if ok, _ := s.RemoveFriend(bg, a, b); !ok {
		t.Fatal("remove should succeed")
	}
	if f, _ := s.AreFriends(bg, a, b); f {
		t.Fatal("edge should be gone")
	}
}

func TestPG_DirectoryAndKeyring(t *testing.T) {
	s := pgStore(t)
	_ = s.UpsertDirDevice(bg, 7, "Mona", strptr("Mona L"), "mac", "ka-mac")
	_ = s.UpsertDirDevice(bg, 7, "mona", nil, "win", "ka-win")
	acct, _ := s.DirAccountByHandle(bg, "@MONA")
	if acct == nil || acct.GitHubID != 7 || len(acct.Devices) != 2 || acct.Devices["win"] != "ka-win" {
		t.Fatalf("directory: %+v", acct)
	}
	if missing, _ := s.DirAccountByHandle(bg, "nobody"); missing != nil {
		t.Fatal("unknown handle should be nil")
	}

	_ = s.AppendKeyRotation(bg, "ws1", raw(`{"v":1}`))
	_ = s.AppendKeyRotation(bg, "ws1", raw(`{"v":2}`))
	kr, _ := s.KeyRotations(bg, "ws1")
	if len(kr) != 2 || string(kr[0]) != `{"v":1}` || string(kr[1]) != `{"v":2}` {
		t.Fatalf("keyring order: %v", kr)
	}
}

func TestPG_FriendCapAndExpiry(t *testing.T) {
	s := pgStore(t)
	a, b, c := accountKey(1), accountKey(2), accountKey(3)
	r1, _ := s.CreateFriendRequest(bg, a, "a", b, "b", 0, capOf(1))
	_, _ = s.AcceptFriendRequest(bg, r1.ID, b, capOf(1))
	if _, err := s.CreateFriendRequest(bg, a, "a", c, "c", 0, capOf(1)); err != ErrCapReached {
		t.Fatalf("cap should block: %v", err)
	}

	// Expiry: a stale pending request drops from incoming and stops blocking.
	s2 := pgStore(t)
	x, y := accountKey(10), accountKey(11)
	old, _ := s2.CreateFriendRequest(bg, x, "x", y, "y", 0, nil)
	later := int64(requestTTLSecs + 10)
	if in, _ := s2.IncomingRequests(bg, y, later); len(in) != 0 {
		t.Fatal("stale request should expire")
	}
	again, _ := s2.CreateFriendRequest(bg, x, "x", y, "y", later, nil)
	if again.ID == old.ID {
		t.Fatal("expired request should not block a fresh one")
	}
}

// Ensure the pool type assertion path stays valid.
var _ = pgxpool.Pool{}
