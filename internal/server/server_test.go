package server

import (
	"net"
	"net/http"
	"net/http/httptest"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"

	"golang.zx2c4.com/wireguard/wgctrl/wgtypes"

	"github.com/example/wireguard-gateway/internal/peers"
	templater "github.com/example/wireguard-gateway/internal/template"
)

type stubManager struct {
	added   int
	removed int
}

func (m *stubManager) AddPeer(publicKey wgtypes.Key, preshared *wgtypes.Key, allowedIPs []net.IPNet) error {
	m.added++
	return nil
}

func (m *stubManager) RemovePeer(publicKey wgtypes.Key) error {
	m.removed++
	return nil
}

func (m *stubManager) Handshakes() (map[string]time.Time, error) {
	return map[string]time.Time{}, nil
}

func TestCreatePeerIPv6Forbidden(t *testing.T) {
	dir := t.TempDir()
	tplPath := filepath.Join(dir, "resp.tmpl")
	if err := os.WriteFile(tplPath, []byte(`{"ok":true}`), 0o600); err != nil {
		t.Fatalf("write template: %v", err)
	}

	renderer, err := templater.NewRenderer(tplPath)
	if err != nil {
		t.Fatalf("renderer: %v", err)
	}

	store := peers.NewStore()
	mgr := &stubManager{}

	srv, err := New(Options{
		ListenAddr:             "",
		Interface:              "wg0",
		Endpoint:               "example.com:51820",
		Renderer:               renderer,
		PeerStore:              store,
		Manager:                mgr,
		TrustProxyLoopbackOnly: true,
	})
	if err != nil {
		t.Fatalf("New server: %v", err)
	}

	req := httptest.NewRequest(http.MethodPost, "/peer", nil)
	req.RemoteAddr = "[2001:db8::1]:12345"
	rr := httptest.NewRecorder()

	srv.Handler().ServeHTTP(rr, req)

	if rr.Code != http.StatusForbidden {
		t.Fatalf("expected status %d, got %d", http.StatusForbidden, rr.Code)
	}
	expected := "{\"error\":\"ipv6 not allowed\"}"
	if strings.TrimSpace(rr.Body.String()) != expected {
		t.Fatalf("expected body %s, got %s", expected, rr.Body.String())
	}
	if mgr.added != 0 {
		t.Fatalf("expected AddPeer not called")
	}
}
