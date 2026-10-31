package relay

import (
	"encoding/json"
	"fmt"
	"net/http"
	"net/http/httptest"
	"strconv"
	"strings"
	"testing"
)

// pagingStore is what the paging tests need from a backend.
type pagingStore interface {
	Store
	envelopePager
}

// fillEnvelopes appends n small envelopes to ws (seqs 1..n on a fresh store).
func fillEnvelopes(t *testing.T, st Store, ws string, n int) {
	t.Helper()
	for i := 1; i <= n; i++ {
		if _, err := st.AppendEnvelope(bg, ws, raw(fmt.Sprintf(`{"n":%d}`, i)), ""); err != nil {
			t.Fatalf("append %d: %v", i, err)
		}
	}
}

// walkPages follows a store's pages from 0 and returns every seq seen.
func walkPages(t *testing.T, st envelopePager, ws string, limit, maxBytes int) (seqs []uint64, pages int) {
	t.Helper()
	after := uint64(0)
	for {
		rows, more, err := st.EnvelopesPage(bg, ws, after, limit, maxBytes)
		if err != nil {
			t.Fatalf("page after %d: %v", after, err)
		}
		pages++
		for _, r := range rows {
			seqs = append(seqs, r.Seq)
			after = r.Seq
		}
		if !more {
			return seqs, pages
		}
		if len(rows) == 0 {
			t.Fatalf("more=true with an empty page after %d", after)
		}
		if pages > 10000 {
			t.Fatal("paging did not terminate")
		}
	}
}

func assertContiguous(t *testing.T, seqs []uint64, n int) {
	t.Helper()
	if len(seqs) != n {
		t.Fatalf("saw %d envelopes, want %d", len(seqs), n)
	}
	for i, s := range seqs {
		if s != uint64(i+1) {
			t.Fatalf("seq[%d]=%d, want %d (gap or duplicate)", i, s, i+1)
		}
	}
}

// runEnvelopePagingContract is the backend-independent paging contract, run
// against the memory store and (when TEST_DATABASE_URL is set) Postgres.
func runEnvelopePagingContract(t *testing.T, st pagingStore) {
	fillEnvelopes(t, st, "ws", 25)
	fillEnvelopes(t, st, "other", 3) // another room never leaks into a page

	// Count-bounded pages walk the whole log exactly once.
	seqs, pages := walkPages(t, st, "ws", 10, 1<<20)
	assertContiguous(t, seqs, 25)
	if pages != 3 {
		t.Fatalf("25 envelopes at limit 10 took %d pages, want 3", pages)
	}

	// A page that ends exactly at the head reports no more.
	rows, more, err := st.EnvelopesPage(bg, "ws", 15, 10, 1<<20)
	if err != nil || len(rows) != 10 || more || rows[9].Seq != 25 {
		t.Fatalf("exact tail page: %d rows more=%v err=%v", len(rows), more, err)
	}
	// Past the head: empty, no more.
	rows, more, err = st.EnvelopesPage(bg, "ws", 25, 10, 1<<20)
	if err != nil || len(rows) != 0 || more {
		t.Fatalf("past head: %d rows more=%v err=%v", len(rows), more, err)
	}
	// Unknown room: empty, no more.
	rows, more, err = st.EnvelopesPage(bg, "nope", 0, 10, 1<<20)
	if err != nil || len(rows) != 0 || more {
		t.Fatalf("unknown room: %d rows more=%v err=%v", len(rows), more, err)
	}

	// Byte-bounded: each body is `{"n":N}` (7 or 8 bytes). A 20-byte budget
	// holds two of the 7-byte bodies (seqs 1-9), never a third.
	rows, more, err = st.EnvelopesPage(bg, "ws", 0, 1000, 20)
	if err != nil || len(rows) != 2 || !more || rows[1].Seq != 2 {
		t.Fatalf("byte budget 20: %+v more=%v err=%v", rows, more, err)
	}
	// Budget met exactly (7+7+7 = 21): the next row starts at the budget and
	// must still be reported as "more".
	rows, more, err = st.EnvelopesPage(bg, "ws", 0, 1000, 21)
	if err != nil || len(rows) != 3 || !more {
		t.Fatalf("byte budget 21: %d rows more=%v err=%v", len(rows), more, err)
	}
	// Byte-bounded walk still visits everything exactly once.
	seqs, _ = walkPages(t, st, "ws", 1000, 30)
	assertContiguous(t, seqs, 25)

	// One envelope larger than the whole budget is still returned (alone), so
	// the cursor can always advance past it.
	big := `{"ct":"` + strings.Repeat("A", 200) + `"}`
	if _, err := st.AppendEnvelope(bg, "big", raw(big), ""); err != nil {
		t.Fatal(err)
	}
	fillEnvelopes(t, st, "big", 2)
	rows, more, err = st.EnvelopesPage(bg, "big", 0, 1000, 50)
	if err != nil || len(rows) != 1 || !more || string(rows[0].Body) != big {
		t.Fatalf("oversized first envelope: %d rows more=%v err=%v", len(rows), more, err)
	}
}

func TestEnvelopePagingContract_Memory(t *testing.T) {
	runEnvelopePagingContract(t, newMemoryStore())
}

func TestPG_EnvelopePagingContract(t *testing.T) {
	runEnvelopePagingContract(t, pgStore(t))
}

// listPage does one GET /envelopes and decodes rows + paging headers.
func listPage(t *testing.T, base, ws, query string) (rows []Envelope, more bool, next uint64, body []byte) {
	t.Helper()
	resp, body := do(t, "GET", base+"/v1/workspaces/"+ws+"/envelopes?"+query, "", nil)
	if resp.StatusCode != http.StatusOK {
		t.Fatalf("GET %s: %d %s", query, resp.StatusCode, body)
	}
	if err := json.Unmarshal(body, &rows); err != nil {
		t.Fatalf("body is not a JSON array of envelopes: %v: %.200s", err, body)
	}
	more = resp.Header.Get(headerEnvelopesMore) == "true"
	next, err := strconv.ParseUint(resp.Header.Get(headerEnvelopesNext), 10, 64)
	if err != nil {
		t.Fatalf("missing/invalid %s header: %q", headerEnvelopesNext, resp.Header.Get(headerEnvelopesNext))
	}
	return rows, more, next, body
}

// A paging-aware client (limit + headers) walks a multi-page room exactly once.
func TestEnvelopeListPagesWithLimit(t *testing.T) {
	srv := New(Options{Store: newMemoryStore(), Entitlement: entitlementPolicy{kind: entOpen}})
	ts := httptest.NewServer(srv.Handler())
	defer ts.Close()
	fillEnvelopes(t, srv.store, "ws", 23)

	after := uint64(0)
	var seqs []uint64
	pages := 0
	for {
		rows, more, next, _ := listPage(t, ts.URL, "ws", fmt.Sprintf("after=%d&limit=5", after))
		pages++
		for _, r := range rows {
			seqs = append(seqs, r.Seq)
		}
		if len(rows) > 0 && next != rows[len(rows)-1].Seq {
			t.Fatalf("next-after %d != last seq %d", next, rows[len(rows)-1].Seq)
		}
		after = next
		if !more {
			break
		}
	}
	assertContiguous(t, seqs, 23)
	if pages != 5 {
		t.Fatalf("23 envelopes at limit=5 took %d pages, want 5", pages)
	}

	// Empty page: next-after echoes the cursor, no more.
	rows, more, next, body := listPage(t, ts.URL, "ws", "after=23&limit=5")
	if len(rows) != 0 || more || next != 23 || string(body) != "[]" {
		t.Fatalf("empty page: rows=%d more=%v next=%d body=%s", len(rows), more, next, body)
	}

	// An oversized / bogus limit is clamped, never an error.
	for _, q := range []string{"after=0&limit=999999", "after=0&limit=-3", "after=0&limit=abc", "after=0&limit=0"} {
		rows, more, _, _ := listPage(t, ts.URL, "ws", q)
		if len(rows) != 23 || more {
			t.Fatalf("%s: %d rows more=%v", q, len(rows), more)
		}
	}
}

// A client that predates paging (shipped v1.15.1: no limit, ignores headers,
// sets its cursor to the highest seq it received) still reaches every envelope:
// the server caps its page at the default, and its next poll continues from
// that cursor. The body stays the bare /v1 JSON array.
func TestEnvelopeListLegacyClientCatchesUpAcrossCappedPages(t *testing.T) {
	srv := New(Options{Store: newMemoryStore(), Entitlement: entitlementPolicy{kind: entOpen}})
	ts := httptest.NewServer(srv.Handler())
	defer ts.Close()
	n := defaultEnvelopePageLimit*2 + 37
	fillEnvelopes(t, srv.store, "ws", n)

	cursor := uint64(0)
	var seqs []uint64
	polls := 0
	for {
		resp, body := do(t, "GET", fmt.Sprintf("%s/v1/workspaces/ws/envelopes?after=%d", ts.URL, cursor), "", nil)
		polls++
		var rows []Envelope
		if err := json.Unmarshal(body, &rows); err != nil || resp.StatusCode != 200 {
			t.Fatalf("legacy poll: %d %v", resp.StatusCode, err)
		}
		if polls == 1 {
			if len(rows) != defaultEnvelopePageLimit || resp.Header.Get(headerEnvelopesMore) != "true" {
				t.Fatalf("first legacy page: %d rows, more=%q", len(rows), resp.Header.Get(headerEnvelopesMore))
			}
			// Byte-identical to the pre-paging encoding of the same rows.
			want, _ := json.Marshal(rows)
			if string(body) != string(want) {
				t.Fatal("legacy page body is not the plain /v1 envelope array")
			}
		}
		if len(rows) == 0 {
			break
		}
		for _, r := range rows {
			seqs = append(seqs, r.Seq)
			if r.Seq > cursor {
				cursor = r.Seq
			}
		}
	}
	assertContiguous(t, seqs, n)
	if polls != 4 { // 3 capped pages + the empty "caught up" poll
		t.Fatalf("legacy client took %d polls, want 4", polls)
	}
}

// The byte budget bounds a page even when the count limit would allow more.
func TestEnvelopeListByteBudget(t *testing.T) {
	srv := New(Options{Store: newMemoryStore(), Entitlement: entitlementPolicy{kind: entOpen}})
	ts := httptest.NewServer(srv.Handler())
	defer ts.Close()
	// 10 bodies just over 1 MiB: a 4 MiB budget fits 3 per page.
	body := `{"ct":"` + strings.Repeat("A", 1<<20+100) + `"}`
	for i := 0; i < 10; i++ {
		if _, err := srv.store.AppendEnvelope(bg, "ws", raw(body), ""); err != nil {
			t.Fatal(err)
		}
	}
	rows, more, next, _ := listPage(t, ts.URL, "ws", "after=0")
	if len(rows) != 3 || !more || next != 3 {
		t.Fatalf("byte-capped page: %d rows more=%v next=%d", len(rows), more, next)
	}
	if string(rows[0].Body) != body {
		t.Fatal("body altered")
	}
}

// opaqueStore hides the memory store's EnvelopesPage, standing in for a
// third-party Store that only implements the base interface.
type opaqueStore struct{ Store }

func TestEnvelopeListPagesThirdPartyStore(t *testing.T) {
	inner := newMemoryStore()
	fillEnvelopes(t, inner, "ws", 12)
	srv := New(Options{Store: opaqueStore{inner}, Entitlement: entitlementPolicy{kind: entOpen}})
	ts := httptest.NewServer(srv.Handler())
	defer ts.Close()
	rows, more, next, _ := listPage(t, ts.URL, "ws", "after=0&limit=5")
	if len(rows) != 5 || !more || next != 5 {
		t.Fatalf("fallback page: %d rows more=%v next=%d", len(rows), more, next)
	}
	rows, more, _, _ = listPage(t, ts.URL, "ws", "after=10&limit=5")
	if len(rows) != 2 || more {
		t.Fatalf("fallback tail: %d rows more=%v", len(rows), more)
	}
}
