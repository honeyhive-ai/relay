package relay

import (
	"encoding/json"
	"errors"
	"net"
	"sync"
	"sync/atomic"
	"time"

	"github.com/gorilla/websocket"
)

// tconn wraps one tunnel WebSocket. gorilla/websocket allows one concurrent
// reader and one concurrent writer; Close/WriteControl may run concurrently with
// both. tconn serializes data writes (wmu) and makes closing idempotent.
type tconn struct {
	ws  *websocket.Conn
	hub *tunnelHub

	wmu       sync.Mutex
	closeOnce sync.Once
	closed    chan struct{}
	// hard is a fixed read deadline (unix nanos, 0 = none) that pongs must not
	// extend: the hello/auth window after a challenge.
	hard atomic.Int64
}

func newTconn(ws *websocket.Conn, hub *tunnelHub) *tconn {
	return &tconn{ws: ws, hub: hub, closed: make(chan struct{})}
}

func (t *tconn) isClosed() bool {
	select {
	case <-t.closed:
		return true
	default:
		return false
	}
}

// writeMsg writes one message under the write lock with a deadline, so a peer
// that stops reading can stall a writer for at most writeTimeout.
func (t *tconn) writeMsg(mt int, b []byte) error {
	t.wmu.Lock()
	defer t.wmu.Unlock()
	if t.isClosed() {
		return net.ErrClosed
	}
	_ = t.ws.SetWriteDeadline(time.Now().Add(t.hub.lim.WriteTimeout))
	return t.ws.WriteMessage(mt, b)
}

func (t *tconn) writeJSON(v any) error {
	b, err := json.Marshal(v)
	if err != nil {
		return err
	}
	return t.writeMsg(websocket.TextMessage, b)
}

// fail sends {"t":"error"} then a close frame with the matching code (spec §6).
// The error text is best-effort: it's skipped if a writer is wedged.
func (t *tconn) fail(tc tunnelCode, msg string) {
	t.shutdown(tc.Close, tc.Code, func() {
		if t.wmu.TryLock() {
			_ = t.ws.SetWriteDeadline(time.Now().Add(time.Second))
			b, _ := json.Marshal(map[string]string{"t": "error", "code": tc.Code, "message": msg})
			_ = t.ws.WriteMessage(websocket.TextMessage, b)
			t.wmu.Unlock()
		}
	})
}

// closeWith closes with a code and no error message (splice pass-through).
func (t *tconn) closeWith(code int, reason string) { t.shutdown(code, reason, nil) }

// shutdown sends the close frame, half-closes TCP (so the peer still gets
// everything already written, and we can still read its close reply), and
// fully closes the socket shortly after. Idempotent.
func (t *tconn) shutdown(code int, reason string, before func()) {
	t.closeOnce.Do(func() {
		if before != nil {
			before()
		}
		if len(reason) > 120 {
			reason = reason[:120]
		}
		_ = t.ws.WriteControl(websocket.CloseMessage, websocket.FormatCloseMessage(code, reason), time.Now().Add(time.Second))
		close(t.closed)
		if cw, ok := t.ws.NetConn().(interface{ CloseWrite() error }); ok {
			_ = cw.CloseWrite()
			// Wake any reader soon; the peer's close reply normally ends it first.
			_ = t.ws.SetReadDeadline(time.Now().Add(2 * time.Second))
			time.AfterFunc(2*time.Second, func() { _ = t.ws.Close() })
		} else {
			_ = t.ws.Close()
		}
		t.hub.untrack(t)
	})
}

// abort closes immediately without a close frame (the peer is already gone).
func (t *tconn) abort() {
	t.closeOnce.Do(func() {
		close(t.closed)
		_ = t.ws.Close()
		t.hub.untrack(t)
	})
}

// read reads the next message, first extending the silence deadline (spec §10:
// a peer silent for 60 s is closed). Pongs extend it too (see upgrade).
func (t *tconn) read(deadline time.Duration) (int, []byte, error) {
	t.hard.Store(0)
	_ = t.ws.SetReadDeadline(time.Now().Add(deadline))
	return t.ws.ReadMessage()
}

// readBefore reads with a fixed deadline that keepalive pongs don't extend.
func (t *tconn) readBefore(until time.Time) (int, []byte, error) {
	t.hard.Store(until.UnixNano())
	_ = t.ws.SetReadDeadline(until)
	return t.ws.ReadMessage()
}

// onPong extends the silence deadline, never past a hard deadline.
func (t *tconn) onPong(string) error {
	d := time.Now().Add(t.hub.lim.PeerSilence)
	if h := t.hard.Load(); h != 0 && time.Unix(0, h).Before(d) {
		d = time.Unix(0, h)
	}
	return t.ws.SetReadDeadline(d)
}

// pinger sends a WebSocket ping every interval until the conn closes.
func (t *tconn) pinger(interval time.Duration) {
	tick := time.NewTicker(interval)
	defer tick.Stop()
	for {
		select {
		case <-t.closed:
			return
		case <-tick.C:
			if err := t.ws.WriteControl(websocket.PingMessage, nil, time.Now().Add(t.hub.lim.WriteTimeout)); err != nil {
				if errors.Is(err, websocket.ErrCloseSent) {
					return
				}
			}
		}
	}
}

// isTimeout reports whether err is a deadline expiry.
func isTimeout(err error) bool {
	var ne net.Error
	return errors.As(err, &ne) && ne.Timeout()
}

// passCloseCode maps a peer's close to the code relayed to the other side
// (spec §6.5: same code; 1000 and 1001 pass through as 1000).
func passCloseCode(err error) (int, string) {
	var ce *websocket.CloseError
	if errors.As(err, &ce) {
		switch {
		case ce.Code == websocket.CloseNormalClosure, ce.Code == websocket.CloseGoingAway:
			return websocket.CloseNormalClosure, ""
		case ce.Code >= 3000 && ce.Code <= 4999,
			ce.Code == websocket.CloseProtocolError, ce.Code == websocket.CloseUnsupportedData,
			ce.Code == websocket.CloseInvalidFramePayloadData, ce.Code == websocket.ClosePolicyViolation,
			ce.Code == websocket.CloseMessageTooBig, ce.Code == websocket.CloseInternalServerErr:
			return ce.Code, ce.Text
		}
		return websocket.CloseNormalClosure, ""
	}
	if errors.Is(err, websocket.ErrReadLimit) {
		return websocket.CloseMessageTooBig, ""
	}
	return websocket.CloseNormalClosure, ""
}
