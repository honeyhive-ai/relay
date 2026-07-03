package relay

import (
	"context"
	"encoding/json"
	"errors"
	"testing"
)

var bg = context.Background()

func strptr(s string) *string { return &s }

func raw(s string) json.RawMessage { return json.RawMessage(s) }

func capOf(n int) *int { return &n }

// ── Account registry + inbox ──────────────────────────────────────────────────

func TestTwoDevicesShareOneAccountAndInbox(t *testing.T) {
	s := newMemoryStore()
	_, _ = s.RegisterAccountDevice(bg, 42, "Octocat", "devA", strptr("nodeA"), nil, 100)
	_, _ = s.RegisterAccountDevice(bg, 42, "octocat", "devB", strptr("nodeB"), nil, 101)

	key := accountKey(42)
	if devs, _ := s.AccountDevices(bg, key); len(devs) != 2 {
		t.Fatalf("want 2 devices, got %d", len(devs))
	}
	if k, ok, _ := s.AccountKeyForLogin(bg, "@OCTOCAT"); !ok || k != key {
		t.Fatalf("login index miss: %q %v", k, ok)
	}
	seq, _ := s.PushAccountEvent(bg, key, raw(`{"kind":"ping"}`))
	if seq != 1 {
		t.Fatalf("want seq 1, got %d", seq)
	}
	rows, _ := s.AccountInboxAfter(bg, key, 0)
	if len(rows) != 1 || rows[0].Seq != 1 {
		t.Fatalf("inbox after 0: %+v", rows)
	}
	if rows, _ := s.AccountInboxAfter(bg, key, 1); len(rows) != 0 {
		t.Fatalf("inbox after 1 should be empty, got %d", len(rows))
	}
}

func TestInboxSequenceMonotonic(t *testing.T) {
	s := newMemoryStore()
	key := accountKey(7)
	for want := uint64(1); want <= 3; want++ {
		if got, _ := s.PushAccountEvent(bg, key, raw(`{}`)); got != want {
			t.Fatalf("seq want %d got %d", want, got)
		}
	}
	if rows, _ := s.AccountInboxAfter(bg, key, 1); len(rows) != 2 {
		t.Fatalf("want 2 rows after 1, got %d", len(rows))
	}
}

func TestHeartbeatOnlyRegisteredDevices(t *testing.T) {
	s := newMemoryStore()
	_, _ = s.RegisterAccountDevice(bg, 9, "user", "dev1", nil, nil, 1000)
	if ok, _ := s.HeartbeatDevice(bg, 9, "dev1", 2000); !ok {
		t.Fatal("registered device heartbeat should succeed")
	}
	if ok, _ := s.HeartbeatDevice(bg, 9, "ghost", 2000); ok {
		t.Fatal("unknown device heartbeat should fail")
	}
	devs, _ := s.AccountDevices(bg, accountKey(9))
	if devs[0].LastSeen != 2000 {
		t.Fatalf("last_seen not updated: %d", devs[0].LastSeen)
	}
}

func TestUnknownAccountPollsEmpty(t *testing.T) {
	s := newMemoryStore()
	if rows, _ := s.AccountInboxAfter(bg, "github:999", 0); len(rows) != 0 {
		t.Fatal("unknown inbox should be empty")
	}
	if devs, _ := s.AccountDevices(bg, "github:999"); len(devs) != 0 {
		t.Fatal("unknown devices should be empty")
	}
	if _, ok, _ := s.AccountKeyForLogin(bg, "nobody"); ok {
		t.Fatal("unknown login should miss")
	}
}

// ── Friend graph ──────────────────────────────────────────────────────────────

func TestRequestAcceptCreatesSymmetricEdge(t *testing.T) {
	s := newMemoryStore()
	_, _ = s.RegisterAccountDevice(bg, 1, "alice", "d1", nil, nil, 0)
	_, _ = s.RegisterAccountDevice(bg, 2, "bob", "d2", nil, nil, 0)
	a, b := accountKey(1), accountKey(2)
	req, err := s.CreateFriendRequest(bg, a, "alice", b, "bob", 10, nil)
	if err != nil {
		t.Fatal(err)
	}
	if f, _ := s.AreFriends(bg, a, b); f {
		t.Fatal("not friends until accepted")
	}
	acc, err := s.AcceptFriendRequest(bg, req.ID, b, nil)
	if err != nil || acc.State != StateAccepted {
		t.Fatalf("accept: %v state=%s", err, acc.State)
	}
	if f, _ := s.AreFriends(bg, a, b); !f {
		t.Fatal("should be friends a-b")
	}
	if f, _ := s.AreFriends(bg, b, a); !f {
		t.Fatal("should be friends b-a")
	}
	if n, _ := s.FriendCount(bg, a); n != 1 {
		t.Fatalf("friend count %d", n)
	}
	friends, _ := s.ListFriends(bg, a)
	if len(friends) != 1 || friends[0].Login != "bob" {
		t.Fatalf("list friends: %+v", friends)
	}
}

func TestOnlyRecipientCanAcceptPending(t *testing.T) {
	s := newMemoryStore()
	a, b, c := accountKey(1), accountKey(2), accountKey(3)
	req, _ := s.CreateFriendRequest(bg, a, "a", b, "b", 0, nil)
	if _, err := s.AcceptFriendRequest(bg, req.ID, c, nil); !errors.Is(err, ErrNotYours) {
		t.Fatalf("third party accept: %v", err)
	}
	if _, err := s.AcceptFriendRequest(bg, req.ID, a, nil); !errors.Is(err, ErrNotYours) {
		t.Fatalf("sender accept: %v", err)
	}
	if _, err := s.AcceptFriendRequest(bg, req.ID, b, nil); err != nil {
		t.Fatal(err)
	}
	if _, err := s.AcceptFriendRequest(bg, req.ID, b, nil); !errors.Is(err, ErrNotPending) {
		t.Fatalf("second accept: %v", err)
	}
}

func TestDuplicateIdempotentAndSelfRejected(t *testing.T) {
	s := newMemoryStore()
	a, b := accountKey(1), accountKey(2)
	r1, _ := s.CreateFriendRequest(bg, a, "a", b, "b", 0, nil)
	r2, _ := s.CreateFriendRequest(bg, a, "a", b, "b", 0, nil)
	if r1.ID != r2.ID {
		t.Fatal("duplicate pending should be idempotent")
	}
	if _, err := s.CreateFriendRequest(bg, a, "a", a, "a", 0, nil); !errors.Is(err, ErrSelfRequest) {
		t.Fatalf("self request: %v", err)
	}
}

func TestRejectClosesWithoutEdge(t *testing.T) {
	s := newMemoryStore()
	a, b := accountKey(1), accountKey(2)
	req, _ := s.CreateFriendRequest(bg, a, "a", b, "b", 0, nil)
	closed, err := s.CloseFriendRequest(bg, req.ID, b)
	if err != nil || closed.State != StateRejected {
		t.Fatalf("reject: %v state=%s", err, closed.State)
	}
	if f, _ := s.AreFriends(bg, a, b); f {
		t.Fatal("reject should not create edge")
	}
	if in, _ := s.IncomingRequests(bg, b, 1); len(in) != 0 {
		t.Fatal("rejected drops from incoming")
	}
}

func TestCancelBySenderUsesCancelled(t *testing.T) {
	s := newMemoryStore()
	a, b := accountKey(1), accountKey(2)
	req, _ := s.CreateFriendRequest(bg, a, "a", b, "b", 0, nil)
	closed, err := s.CloseFriendRequest(bg, req.ID, a)
	if err != nil || closed.State != StateCancelled {
		t.Fatalf("cancel: %v state=%s", err, closed.State)
	}
}

func TestRemoveFriendDropsEdge(t *testing.T) {
	s := newMemoryStore()
	a, b := accountKey(1), accountKey(2)
	req, _ := s.CreateFriendRequest(bg, a, "a", b, "b", 0, nil)
	_, _ = s.AcceptFriendRequest(bg, req.ID, b, nil)
	if ok, _ := s.RemoveFriend(bg, a, b); !ok {
		t.Fatal("remove should succeed")
	}
	if f, _ := s.AreFriends(bg, a, b); f {
		t.Fatal("edge should be gone")
	}
	if ok, _ := s.RemoveFriend(bg, a, b); ok {
		t.Fatal("second remove should be false")
	}
}

func TestAlreadyFriendsRejected(t *testing.T) {
	s := newMemoryStore()
	a, b := accountKey(1), accountKey(2)
	req, _ := s.CreateFriendRequest(bg, a, "a", b, "b", 0, nil)
	_, _ = s.AcceptFriendRequest(bg, req.ID, b, nil)
	if _, err := s.CreateFriendRequest(bg, a, "a", b, "b", 0, nil); !errors.Is(err, ErrAlreadyFriends) {
		t.Fatalf("already friends: %v", err)
	}
}

func TestFriendCapBlocksRequestAndAccept(t *testing.T) {
	s := newMemoryStore()
	a, b, c := accountKey(1), accountKey(2), accountKey(3)
	r1, _ := s.CreateFriendRequest(bg, a, "a", b, "b", 0, capOf(1))
	_, _ = s.AcceptFriendRequest(bg, r1.ID, b, capOf(1))
	if _, err := s.CreateFriendRequest(bg, a, "a", c, "c", 0, capOf(1)); !errors.Is(err, ErrCapReached) {
		t.Fatalf("cap should block request: %v", err)
	}

	// A request predating the cap being hit: accept re-checks it.
	s2 := newMemoryStore()
	pending, _ := s2.CreateFriendRequest(bg, c, "c", a, "a", 0, capOf(1))
	r, _ := s2.CreateFriendRequest(bg, b, "b", a, "a", 0, capOf(1))
	if _, err := s2.AcceptFriendRequest(bg, r.ID, a, capOf(1)); err != nil {
		t.Fatal(err)
	}
	if _, err := s2.AcceptFriendRequest(bg, pending.ID, a, capOf(1)); !errors.Is(err, ErrCapReached) {
		t.Fatalf("cap should block accept: %v", err)
	}
}

// ── Presence + abuse controls ─────────────────────────────────────────────────

func TestPresenceMapsLastSeen(t *testing.T) {
	cases := []struct {
		lastSeen, now int64
		want          string
	}{
		{0, 1000, "offline"},
		{1000, 1000, "online"},
		{1000, 1000 + 60, "online"},
		{1000, 1000 + 200, "away"},
		{1000, 1000 + 1000, "offline"},
	}
	for _, c := range cases {
		if got := presenceStr(c.lastSeen, c.now); got != c.want {
			t.Errorf("presenceStr(%d,%d)=%q want %q", c.lastSeen, c.now, got, c.want)
		}
	}
}

func TestFriendPresenceReflectsHeartbeatAndAppearOffline(t *testing.T) {
	s := newMemoryStore()
	_, _ = s.RegisterAccountDevice(bg, 1, "alice", "d1", nil, nil, 0)
	_, _ = s.RegisterAccountDevice(bg, 2, "bob", "d2", nil, nil, 0)
	a, b := accountKey(1), accountKey(2)
	req, _ := s.CreateFriendRequest(bg, a, "alice", b, "bob", 0, nil)
	_, _ = s.AcceptFriendRequest(bg, req.ID, b, nil)

	_, _ = s.HeartbeatDevice(bg, 2, "d2", 1000)
	if pres, _ := s.FriendPresence(bg, a, 1010); pres[0].Presence != "online" {
		t.Fatalf("want online, got %s", pres[0].Presence)
	}
	if pres, _ := s.FriendPresence(bg, a, 1000+200); pres[0].Presence != "away" {
		t.Fatalf("want away, got %s", pres[0].Presence)
	}
	if pres, _ := s.FriendPresence(bg, a, 1000+1000); pres[0].Presence != "offline" {
		t.Fatalf("want offline, got %s", pres[0].Presence)
	}

	_, _ = s.HeartbeatDevice(bg, 2, "d2", 2000)
	_ = s.SetVisibility(bg, 2, true)
	if pres, _ := s.FriendPresence(bg, a, 2000); pres[0].Presence != "offline" {
		t.Fatalf("appear-offline should force offline, got %s", pres[0].Presence)
	}
}

func TestPendingRequestsExpire(t *testing.T) {
	s := newMemoryStore()
	a, b := accountKey(1), accountKey(2)
	req, _ := s.CreateFriendRequest(bg, a, "a", b, "b", 0, nil)
	if in, _ := s.IncomingRequests(bg, b, 100); len(in) != 1 {
		t.Fatal("should have 1 incoming")
	}
	later := int64(requestTTLSecs + 10)
	if in, _ := s.IncomingRequests(bg, b, later); len(in) != 0 {
		t.Fatal("should expire past TTL")
	}
	again, _ := s.CreateFriendRequest(bg, a, "a", b, "b", later, nil)
	if again.ID == req.ID {
		t.Fatal("stale request should not block a fresh one")
	}
}

func TestTooManyPendingOutbound(t *testing.T) {
	s := newMemoryStore()
	from := accountKey(1)
	for i := 0; i < maxPendingOutbound; i++ {
		if _, err := s.CreateFriendRequest(bg, from, "me", accountKey(uint64(100+i)), "t", 0, nil); err != nil {
			t.Fatal(err)
		}
	}
	if _, err := s.CreateFriendRequest(bg, from, "me", accountKey(999), "t", 0, nil); !errors.Is(err, ErrTooManyPending) {
		t.Fatalf("want TooManyPending, got %v", err)
	}
}

func TestFriendDevicesVisibleOnlyBetweenFriends(t *testing.T) {
	s := newMemoryStore()
	_, _ = s.RegisterAccountDevice(bg, 1, "alice", "d1", strptr("node-a"), nil, 0)
	_, _ = s.RegisterAccountDevice(bg, 2, "bob", "d2", strptr("node-b"), nil, 0)
	a, b, stranger := accountKey(1), accountKey(2), accountKey(3)
	if _, ok, _ := s.FriendDevices(bg, a, b); ok {
		t.Fatal("strangers should not see devices")
	}
	req, _ := s.CreateFriendRequest(bg, a, "alice", b, "bob", 0, nil)
	_, _ = s.AcceptFriendRequest(bg, req.ID, b, nil)
	rows, ok, _ := s.FriendDevices(bg, a, b)
	if !ok || len(rows) != 1 || rows[0].NodeID == nil || *rows[0].NodeID != "node-b" {
		t.Fatalf("friend devices: ok=%v rows=%+v", ok, rows)
	}
	if _, ok, _ := s.FriendDevices(bg, stranger, a); ok {
		t.Fatal("non-friend should not see devices")
	}
}

func TestInboxEventShapes(t *testing.T) {
	s := newMemoryStore()
	a, b := accountKey(1), accountKey(2)
	req, _ := s.CreateFriendRequest(bg, a, "alice", b, "bob", 7, nil)
	var ev map[string]any
	_ = json.Unmarshal(req.requestEvent(), &ev)
	if ev["kind"] != "friendRequest" || ev["fromLogin"] != "alice" || ev["requestId"] != req.ID {
		t.Fatalf("request event: %+v", ev)
	}
	acc, _ := s.AcceptFriendRequest(bg, req.ID, b, nil)
	var rev map[string]any
	_ = json.Unmarshal(acc.resolvedEvent(), &rev)
	if rev["kind"] != "friendResolved" || rev["state"] != "accepted" {
		t.Fatalf("resolved event: %+v", rev)
	}
}
