package relay

import (
	"context"
	"net/http"
	"strconv"
)

// Envelope paging.
//
// GET /v1/workspaces/{id}/envelopes used to return every envelope past the
// cursor in one response. A room that had accumulated ~17k envelopes (≈75 MB of
// JSON) made a from-zero fetch — every new device's first sync — materialize the
// whole room, marshal it into one buffer and copy it again, which OOM-killed the
// 512 MB relay machine; the edge proxy then answered 502 to that client and every
// other in-flight request.
//
// The route now returns at most one bounded page: no more than limit envelopes
// and, past the first, no more than envelopePageMaxBytes of stored body bytes.
// The body is still the bare JSON array (byte-compatible with /v1), so a client
// that knows nothing about paging keeps its cursor at the last seq it received
// and the next poll continues from there. A client that does know reads the
// headers below and loops until X-Hive-More is absent.
const (
	// defaultEnvelopePageLimit applies when the client sends no limit — which is
	// every client released before paging existed.
	defaultEnvelopePageLimit = 1000
	// maxEnvelopePageLimit caps an explicit limit.
	maxEnvelopePageLimit = 1000
	// envelopePageMaxBytes bounds a page by stored body size. One envelope is
	// always returned even if it alone exceeds this, so the cursor can advance.
	envelopePageMaxBytes = 4 << 20

	// headerEnvelopesMore is "true" when envelopes past this page exist.
	headerEnvelopesMore = "X-Hive-More"
	// headerEnvelopesNext is the cursor to send as after= for the next page:
	// the last seq in this page (or the request's after when the page is empty).
	headerEnvelopesNext = "X-Hive-Next-After"
)

// envelopePager is implemented by stores that can produce a bounded page
// without loading the whole tail of the log. Stores that don't implement it
// (third-party Store implementations) are paged by trimming EnvelopesAfter,
// which is correct but not memory-bounded.
type envelopePager interface {
	EnvelopesPage(ctx context.Context, workspace string, after uint64, limit, maxBytes int) (rows []Envelope, more bool, err error)
}

// pageBuilder accumulates envelopes into a page under a count and byte budget.
type pageBuilder struct {
	limit, maxBytes int
	bytes           int
	rows            []Envelope
}

func newPageBuilder(limit, maxBytes int) *pageBuilder {
	return &pageBuilder{limit: limit, maxBytes: maxBytes, rows: []Envelope{}}
}

// add appends e if it fits; false means the page is full and e (and everything
// after it) belongs to a later page.
func (p *pageBuilder) add(e Envelope) bool {
	if len(p.rows) >= p.limit {
		return false
	}
	if len(p.rows) > 0 && p.bytes+len(e.Body) > p.maxBytes {
		return false
	}
	p.bytes += len(e.Body)
	p.rows = append(p.rows, e)
	return true
}

// pageEnvelopes returns one bounded page from any Store.
func pageEnvelopes(ctx context.Context, st Store, workspace string, after uint64, limit, maxBytes int) ([]Envelope, bool, error) {
	if p, ok := st.(envelopePager); ok {
		return p.EnvelopesPage(ctx, workspace, after, limit, maxBytes)
	}
	all, err := st.EnvelopesAfter(ctx, workspace, after)
	if err != nil {
		return nil, false, err
	}
	pb := newPageBuilder(limit, maxBytes)
	for _, e := range all {
		if !pb.add(e) {
			return pb.rows, true, nil
		}
	}
	return pb.rows, false, nil
}

// limitParam reads ?limit=, clamped to [1, maxEnvelopePageLimit]. Absent or
// unparsable means the default.
func limitParam(r *http.Request) int {
	n, err := strconv.Atoi(r.URL.Query().Get("limit"))
	if err != nil || n <= 0 {
		return defaultEnvelopePageLimit
	}
	if n > maxEnvelopePageLimit {
		return maxEnvelopePageLimit
	}
	return n
}
