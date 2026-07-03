package relay

import (
	"encoding/json"
	"fmt"
	"os"
	"path/filepath"
)

// Durable persistence for memoryStore: snapshot the durable maps to a JSON file
// on a persistent volume and reload on boot. This matches the single-instance
// deployment model (one relay, one volume); horizontal scaling is postgresStore's
// job. Ephemeral state (pairing codes, candidate/presence blobs) is rebuilt and
// intentionally not persisted here — only the social graph + message history are.
//
// Enable by pointing HIVE_RELAY_DATA_DIR at a writable directory; unset ⇒
// in-memory only.

const snapshotFile = "relay-state.json"

type snapshot struct {
	Workspaces  map[string]wsSnap        `json:"workspaces"`
	Directory   map[string]dirSnap       `json:"directory"`
	Accounts    map[string]acctSnap      `json:"accounts"`
	LoginIndex  map[string]string        `json:"loginIndex"`
	FriendReqs  map[string]FriendRequest `json:"friendRequests"`
	FriendEdges [][2]string              `json:"friendEdges"`
}

type wsSnap struct {
	Envelopes  []Envelope                 `json:"envelopes"`
	NextSeq    uint64                     `json:"nextSeq"`
	Candidates map[string]json.RawMessage `json:"candidates"`
	Presence   map[string]json.RawMessage `json:"presence"`
	Keyring    []json.RawMessage          `json:"keyring"`
}

type dirSnap struct {
	GitHubID uint64            `json:"githubId"`
	Login    string            `json:"login"`
	Name     *string           `json:"name"`
	Devices  map[string]string `json:"devices"`
}

type acctSnap struct {
	Login         string             `json:"login"`
	AppearOffline bool               `json:"appearOffline"`
	Inbox         []InboxRow         `json:"inbox"`
	NextSeq       uint64             `json:"nextSeq"`
	Devices       map[string]devSnap `json:"devices"`
}

type devSnap struct {
	NodeID   *string `json:"nodeId"`
	Label    *string `json:"label"`
	LastSeen int64   `json:"lastSeen"`
}

// newMemoryStoreWithPersistence builds an in-memory store backed by a snapshot
// at data_dir: load any existing snapshot, then remember the path so flushSnapshot
// can write to it. A missing/corrupt snapshot is treated as empty (logged), so a
// fresh volume starts blank rather than failing to boot.
func newMemoryStoreWithPersistence(dataDir string) *memoryStore {
	s := newMemoryStore()
	path := filepath.Join(dataDir, snapshotFile)
	s.persistPath = path

	bytes, err := os.ReadFile(path)
	switch {
	case err == nil:
		var snap snapshot
		if jerr := json.Unmarshal(bytes, &snap); jerr != nil {
			fmt.Fprintf(os.Stderr, "hive-relay: snapshot at %s is unreadable (%v); starting empty\n", path, jerr)
		} else {
			s.restore(snap)
			fmt.Fprintf(os.Stderr, "hive-relay: loaded state snapshot from %s\n", path)
		}
	case os.IsNotExist(err):
		fmt.Fprintf(os.Stderr, "hive-relay: no snapshot at %s yet; starting empty\n", path)
	default:
		fmt.Fprintf(os.Stderr, "hive-relay: could not read %s (%v); starting empty\n", path, err)
	}
	return s
}

func (s *memoryStore) restore(snap snapshot) {
	s.mu.Lock()
	defer s.mu.Unlock()

	s.workspaces = map[string]*memWorkspace{}
	for id, w := range snap.Workspaces {
		cand := w.Candidates
		if cand == nil {
			cand = map[string]json.RawMessage{}
		}
		pres := w.Presence
		if pres == nil {
			pres = map[string]json.RawMessage{}
		}
		s.workspaces[id] = &memWorkspace{
			envelopes:  w.Envelopes,
			nextSeq:    w.NextSeq,
			candidates: cand,
			presence:   pres,
			keyring:    w.Keyring,
		}
	}

	s.directory = map[string]*DirAccount{}
	for k, d := range snap.Directory {
		devs := d.Devices
		if devs == nil {
			devs = map[string]string{}
		}
		s.directory[k] = &DirAccount{GitHubID: d.GitHubID, Login: d.Login, Name: d.Name, Devices: devs}
	}

	s.accounts = map[string]*memAccount{}
	for k, a := range snap.Accounts {
		devs := map[string]memDeviceReg{}
		for id, d := range a.Devices {
			devs[id] = memDeviceReg{nodeID: d.NodeID, label: d.Label, lastSeen: d.LastSeen}
		}
		s.accounts[k] = &memAccount{
			login:         a.Login,
			appearOffline: a.AppearOffline,
			inbox:         a.Inbox,
			nextSeq:       a.NextSeq,
			devices:       devs,
		}
	}

	s.loginIndex = map[string]string{}
	for k, v := range snap.LoginIndex {
		s.loginIndex[k] = v
	}

	s.friendReqs = map[string]*FriendRequest{}
	for id := range snap.FriendReqs {
		r := snap.FriendReqs[id]
		s.friendReqs[id] = &r
	}

	s.friendEdges = map[[2]string]struct{}{}
	for _, pair := range snap.FriendEdges {
		s.friendEdges[pair] = struct{}{}
	}
}

func (s *memoryStore) toSnapshot() snapshot {
	s.mu.RLock()
	defer s.mu.RUnlock()

	snap := snapshot{
		Workspaces:  map[string]wsSnap{},
		Directory:   map[string]dirSnap{},
		Accounts:    map[string]acctSnap{},
		LoginIndex:  map[string]string{},
		FriendReqs:  map[string]FriendRequest{},
		FriendEdges: [][2]string{},
	}
	for id, w := range s.workspaces {
		snap.Workspaces[id] = wsSnap{
			Envelopes: w.envelopes, NextSeq: w.nextSeq,
			Candidates: w.candidates, Presence: w.presence, Keyring: w.keyring,
		}
	}
	for k, d := range s.directory {
		snap.Directory[k] = dirSnap{GitHubID: d.GitHubID, Login: d.Login, Name: d.Name, Devices: d.Devices}
	}
	for k, a := range s.accounts {
		devs := map[string]devSnap{}
		for id, d := range a.devices {
			devs[id] = devSnap{NodeID: d.nodeID, Label: d.label, LastSeen: d.lastSeen}
		}
		snap.Accounts[k] = acctSnap{
			Login: a.login, AppearOffline: a.appearOffline,
			Inbox: a.inbox, NextSeq: a.nextSeq, Devices: devs,
		}
	}
	for k, v := range s.loginIndex {
		snap.LoginIndex[k] = v
	}
	for id, r := range s.friendReqs {
		snap.FriendReqs[id] = *r
	}
	for pair := range s.friendEdges {
		snap.FriendEdges = append(snap.FriendEdges, pair)
	}
	return snap
}

// flushSnapshot atomically writes the current state to the snapshot file
// (write-to-temp + rename, so a crash mid-write can't corrupt it). No-op when
// persistence isn't enabled.
func (s *memoryStore) flushSnapshot() error {
	if s.persistPath == "" {
		return nil
	}
	if parent := filepath.Dir(s.persistPath); parent != "" {
		if err := os.MkdirAll(parent, 0o755); err != nil {
			return err
		}
	}
	bytes, err := json.Marshal(s.toSnapshot())
	if err != nil {
		return err
	}
	tmp := s.persistPath + ".tmp"
	if err := os.WriteFile(tmp, bytes, 0o644); err != nil {
		return err
	}
	return os.Rename(tmp, s.persistPath)
}
