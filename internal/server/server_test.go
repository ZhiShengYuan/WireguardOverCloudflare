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

	"github.com/golang-jwt/jwt/v5"
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

	const jwtSecret = "test-secret"
	srv, err := New(Options{
		ListenAddr:             "",
		Interface:              "wg0",
		Endpoint:               "example.com:51820",
		Renderer:               renderer,
		PeerStore:              store,
		Manager:                mgr,
		TrustProxyLoopbackOnly: true,
		BasicAuthUsername:      "user",
		BasicAuthPassword:      "pass",
		JWTSecret:              jwtSecret,
	})
	if err != nil {
		t.Fatalf("New server: %v", err)
	}

	token := jwt.NewWithClaims(jwt.SigningMethodHS256, jwt.MapClaims{"sub": "test"})
	signed, err := token.SignedString([]byte(jwtSecret))
	if err != nil {
		t.Fatalf("sign token: %v", err)
	}

	req := httptest.NewRequest(http.MethodPost, "/peer", nil)
	req.RemoteAddr = "[2001:db8::1]:12345"
	req.Header.Set("Authorization", "Bearer "+signed)
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
