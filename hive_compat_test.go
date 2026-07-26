package relay

import (
	"bytes"
	"encoding/json"
	"os"
	"path/filepath"
	"testing"
)

// TestHiveEnvelopeCompat guards the relay↔hive wire contract. The fixtures in
// testdata/hive_envelopes are the exact sealed bodies hive's RelayClient POSTs
// to /v1/workspaces/{id}/envelopes (a SealedEnvelope: ciphertext + nonce +
// version), captured from hive's real seal path. They deliberately include
// event kinds added AFTER this relay was written — workspaceHostsUpdated and a
// config-log memberAdded — because hive keeps adding SessionEvent variants and
// they all ride this one opaque body.
//
// The relay is content-blind (store.go carries bodies as json.RawMessage), so
// the guarantee we assert is: (1) a sealed body carries no event plaintext, and
// (2) the relay stores and returns it byte-for-byte. This runs in the relay's
// own CI with no hive toolchain; regenerate the fixtures from hive if the
// envelope encoding ever changes.
func TestHiveEnvelopeCompat(t *testing.T) {
	files, err := filepath.Glob("testdata/hive_envelopes/*.json")
	if err != nil {
		t.Fatalf("glob fixtures: %v", err)
	}
	if len(files) == 0 {
		t.Fatal("no hive envelope fixtures found under testdata/hive_envelopes")
	}
	// Event content that must NEVER appear in a sealed body (kinds + payload).
	leakMarkers := []string{"workspaceHostsUpdated", "memberAdded", "prod-box", "dev-1"}

	ts := testServer(entitlementPolicy{kind: entOpen}, nil)
	defer ts.Close()

	for _, f := range files {
		raw, err := os.ReadFile(f)
		if err != nil {
			t.Fatalf("read %s: %v", f, err)
		}
		body := bytes.TrimSpace(raw)

		// (1) It's a sealed envelope, and no event plaintext leaks through.
		var sealed struct {
			Ciphertext []byte `json:"ciphertext"`
			Nonce      []byte `json:"nonce"`
			Version    int    `json:"version"`
		}
		if err := json.Unmarshal(body, &sealed); err != nil {
			t.Fatalf("%s: not a sealed envelope: %v", f, err)
		}
		if len(sealed.Ciphertext) == 0 || len(sealed.Nonce) == 0 {
			t.Fatalf("%s: sealed envelope missing ciphertext/nonce", f)
		}
		for _, m := range leakMarkers {
			if bytes.Contains(body, []byte(m)) {
				t.Fatalf("%s: plaintext %q leaked in a sealed body", f, m)
			}
		}

		// (2) The relay round-trips the opaque body byte-for-byte.
		ws := "hive-compat-" + filepath.Base(f)
		resp, out := do(t, "POST", ts.URL+"/v1/workspaces/"+ws+"/envelopes", "", json.RawMessage(body))
		if resp.StatusCode != 200 {
			t.Fatalf("%s: POST %d %s", f, resp.StatusCode, out)
		}
		_, out = do(t, "GET", ts.URL+"/v1/workspaces/"+ws+"/envelopes?after=0", "", nil)
		var rows []Envelope
		if err := json.Unmarshal(out, &rows); err != nil {
			t.Fatalf("%s: decode list: %v", f, err)
		}
		if len(rows) != 1 {
			t.Fatalf("%s: want 1 stored envelope, got %d", f, len(rows))
		}
		if !bytes.Equal(bytes.TrimSpace(rows[0].Body), body) {
			t.Fatalf("%s: relay did not preserve the body byte-for-byte\n got: %s\nwant: %s",
				f, rows[0].Body, body)
		}
	}
}
