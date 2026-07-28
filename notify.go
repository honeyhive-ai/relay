package relay

import (
	"context"
	"sync"
)

// wsNotifier is an in-process, per-workspace pub-sub that wakes SSE subscribers
// the instant a new envelope lands, so clients replace their 3s poll with an
// event-driven "pull now" nudge (ROADMAP: kill the 3s poll, step 1).
//
// SINGLE-INSTANCE ONLY. It fans out appends that happen on THIS process; a
// client streaming from instance A will NOT be woken by a write that landed on
// instance B. Cross-instance fan-out (Postgres LISTEN/NOTIFY) is the tracked
// follow-up (#151) — deliberately not built here. Until then the SSE stream is
// still correct for a single relay, and even multi-instance clients keep their
// existing poll as the backstop.
type wsNotifier struct {
	mu   sync.Mutex
	subs map[string]map[chan uint64]struct{} // workspace → set of subscriber channels
}

func newWSNotifier() *wsNotifier {
	return &wsNotifier{subs: map[string]map[chan uint64]struct{}{}}
}

// subscribe registers a subscriber for a workspace's new-seq notifications and
// returns the receive channel plus an unsubscribe func the caller must invoke
// (defer) when it disconnects. The channel is buffered (depth 1) and publish is
// non-blocking, so a slow reader never stalls the append path.
func (n *wsNotifier) subscribe(workspace string) (<-chan uint64, func()) {
	ch := make(chan uint64, 1)
	n.mu.Lock()
	m := n.subs[workspace]
	if m == nil {
		m = map[chan uint64]struct{}{}
		n.subs[workspace] = m
	}
	m[ch] = struct{}{}
	n.mu.Unlock()

	return ch, func() {
		n.mu.Lock()
		if m := n.subs[workspace]; m != nil {
			delete(m, ch)
			if len(m) == 0 {
				delete(n.subs, workspace)
			}
		}
		n.mu.Unlock()
	}
}

// publish nudges every subscriber of workspace with the new seq. Non-blocking:
// if a subscriber's buffer is already full it has a pending wake-up, and since
// the frame is only a "pull after your own cursor" nudge (the seq is
// informational, the client tracks its real cursor) coalescing is safe — the
// pull the pending wake-up triggers is cursor-based and returns everything.
func (n *wsNotifier) publish(workspace string, seq uint64) {
	n.mu.Lock()
	defer n.mu.Unlock()
	for ch := range n.subs[workspace] {
		select {
		case ch <- seq:
		default:
		}
	}
}

// notifyStore is the optional capability a Store exposes when it can push
// per-workspace append notifications in-process. The SSE handler type-asserts
// the Store to this; a store that doesn't implement it still serves the stream
// (preamble + keep-alives), just without instant push. Both built-in stores
// (memory, postgres) implement it.
type notifyStore interface {
	subscribeWorkspace(workspace string) (<-chan uint64, func())
	latestSeq(ctx context.Context, workspace string) (uint64, error)
}
