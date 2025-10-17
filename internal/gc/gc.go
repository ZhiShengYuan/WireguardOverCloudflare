package gc

import (
	"context"
	"log"
	"time"

	"golang.zx2c4.com/wireguard/wgctrl/wgtypes"

	"github.com/example/wireguard-gateway/internal/peers"
)

// Manager provides the subset of WireGuard operations needed for GC.
type Manager interface {
	Handshakes() (map[string]time.Time, error)
	RemovePeer(publicKey wgtypes.Key) error
}

// Options configures the garbage collector.
type Options struct {
	Interval          time.Duration
	Store             *peers.Store
	Manager           Manager
	Interface         string
	Logger            *log.Logger
	NeverConnectedTTL time.Duration
	StaleHandshakeTTL time.Duration
}

// GC periodically removes stale peers.
type GC struct {
	opts    Options
	nowFunc func() time.Time
}

// New constructs a GC runner.
func New(opts Options) *GC {
	if opts.Logger == nil {
		opts.Logger = log.Default()
	}
	return &GC{opts: opts, nowFunc: time.Now}
}

// Run executes the garbage collection loop until context cancellation.
func (g *GC) Run(ctx context.Context) {
	ticker := time.NewTicker(g.opts.Interval)
	defer ticker.Stop()

	for {
		select {
		case <-ctx.Done():
			return
		case <-ticker.C:
			g.runOnce()
		}
	}
}

func (g *GC) runOnce() {
	handshakes, err := g.opts.Manager.Handshakes()
	if err != nil {
		g.opts.Logger.Printf("gc: handshakes: %v", err)
		handshakes = map[string]time.Time{}
	}

	peersList := g.opts.Store.List()
	now := g.nowFunc()

	for _, p := range peersList {
		if t, ok := handshakes[p.PublicKey]; ok && !t.IsZero() {
			if err := g.opts.Store.UpdateHandshake(p.ID, t); err != nil {
				g.opts.Logger.Printf("gc: update handshake for %s: %v", p.ID, err)
			} else {
				p.LastHandshakeAt = &t
			}
		}

		if p.LastHandshakeAt == nil {
			if g.opts.NeverConnectedTTL > 0 && now.Sub(p.CreatedAt) > g.opts.NeverConnectedTTL {
				g.removePeer(p)
			}
			continue
		}

		if g.opts.StaleHandshakeTTL > 0 && now.Sub(*p.LastHandshakeAt) > g.opts.StaleHandshakeTTL {
			g.removePeer(p)
		}
	}
}

func (g *GC) removePeer(p *peers.Peer) {
	removed, err := g.opts.Store.Delete(p.ID)
	if err != nil {
		if err == peers.ErrNotFound {
			return
		}
		g.opts.Logger.Printf("gc: delete store peer %s: %v", p.ID, err)
		return
	}

	key, err := wgtypes.ParseKey(removed.PublicKey)
	if err != nil {
		g.opts.Logger.Printf("gc: parse public key for %s: %v", p.ID, err)
		return
	}

	if err := g.opts.Manager.RemovePeer(key); err != nil {
		g.opts.Logger.Printf("gc: remove peer %s: %v", p.ID, err)
		return
	}

	g.opts.Logger.Printf("gc: removed peer %s due to inactivity", p.ID)
}
