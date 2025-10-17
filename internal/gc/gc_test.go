package gc

import (
	"errors"
	"testing"
	"time"

	"golang.zx2c4.com/wireguard/wgctrl/wgtypes"

	"github.com/example/wireguard-gateway/internal/peers"
)

type fakeManager struct {
	handshakes map[string]time.Time
	removed    []wgtypes.Key
}

func (f *fakeManager) Handshakes() (map[string]time.Time, error) {
	return f.handshakes, nil
}

func (f *fakeManager) RemovePeer(key wgtypes.Key) error {
	f.removed = append(f.removed, key)
	return nil
}

func TestGCRemovesNeverConnectedPeer(t *testing.T) {
	store := peers.NewStore()
	priv, err := wgtypes.GeneratePrivateKey()
	if err != nil {
		t.Fatalf("generate private key: %v", err)
	}
	peer := &peers.Peer{
		ID:        "peer-1",
		PublicKey: priv.PublicKey().String(),
		CreatedAt: time.Unix(0, 0),
	}
	store.Add(peer)

	mgr := &fakeManager{handshakes: map[string]time.Time{}}

	g := New(Options{
		Interval:          time.Minute,
		Store:             store,
		Manager:           mgr,
		NeverConnectedTTL: 10 * time.Minute,
		StaleHandshakeTTL: 24 * time.Hour,
	})
	g.nowFunc = func() time.Time { return time.Unix(0, 0).Add(11 * time.Minute) }

	g.runOnce()

	if _, err := store.Get("peer-1"); !errors.Is(err, peers.ErrNotFound) {
		t.Fatalf("expected peer removed, got err %v", err)
	}
	if len(mgr.removed) != 1 {
		t.Fatalf("expected 1 removed peer, got %d", len(mgr.removed))
	}
}

func TestGCRemovesStaleHandshakePeer(t *testing.T) {
	store := peers.NewStore()
	priv, err := wgtypes.GeneratePrivateKey()
	if err != nil {
		t.Fatalf("generate private key: %v", err)
	}
	handshake := time.Unix(0, 0)
	peer := &peers.Peer{
		ID:              "peer-2",
		PublicKey:       priv.PublicKey().String(),
		CreatedAt:       time.Unix(0, 0),
		LastHandshakeAt: &handshake,
	}
	store.Add(peer)

	mgr := &fakeManager{handshakes: map[string]time.Time{
		priv.PublicKey().String(): handshake,
	}}

	g := New(Options{
		Interval:          time.Minute,
		Store:             store,
		Manager:           mgr,
		NeverConnectedTTL: 10 * time.Minute,
		StaleHandshakeTTL: 24 * time.Hour,
	})
	g.nowFunc = func() time.Time { return time.Unix(0, 0).Add(25 * time.Hour) }

	g.runOnce()

	if _, err := store.Get("peer-2"); !errors.Is(err, peers.ErrNotFound) {
		t.Fatalf("expected peer removed, got err %v", err)
	}
	if len(mgr.removed) != 1 {
		t.Fatalf("expected 1 removed peer, got %d", len(mgr.removed))
	}
}
