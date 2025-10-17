package peers

import (
	"errors"
	"net"
	"sync"
	"time"
)

// Peer represents a managed WireGuard peer.
type Peer struct {
	ID              string
	PublicKey       string
	PrivateKey      string
	PresharedKey    string
	ClientIPv4      net.IP
	AllowedCIDR     string
	Interface       string
	CreatedAt       time.Time
	LastHandshakeAt *time.Time
}

// Store provides concurrent-safe access to peers.
type Store struct {
	mu    sync.RWMutex
	peers map[string]*Peer
}

// ErrNotFound indicates that a peer is missing from the store.
var ErrNotFound = errors.New("peer not found")

// NewStore constructs an empty peer store.
func NewStore() *Store {
	return &Store{peers: make(map[string]*Peer)}
}

// Add inserts a peer into the store.
func (s *Store) Add(peer *Peer) {
	s.mu.Lock()
	defer s.mu.Unlock()
	s.peers[peer.ID] = peer
}

// Get retrieves a peer by ID.
func (s *Store) Get(id string) (*Peer, error) {
	s.mu.RLock()
	defer s.mu.RUnlock()
	peer, ok := s.peers[id]
	if !ok {
		return nil, ErrNotFound
	}
	cp := *peer
	return &cp, nil
}

// Delete removes a peer by ID.
func (s *Store) Delete(id string) (*Peer, error) {
	s.mu.Lock()
	defer s.mu.Unlock()
	peer, ok := s.peers[id]
	if !ok {
		return nil, ErrNotFound
	}
	delete(s.peers, id)
	cp := *peer
	return &cp, nil
}

// List returns a snapshot of all peers.
func (s *Store) List() []*Peer {
	s.mu.RLock()
	defer s.mu.RUnlock()
	out := make([]*Peer, 0, len(s.peers))
	for _, peer := range s.peers {
		cp := *peer
		out = append(out, &cp)
	}
	return out
}

// UpdateHandshake sets the last handshake time for a peer.
func (s *Store) UpdateHandshake(id string, t time.Time) error {
	s.mu.Lock()
	defer s.mu.Unlock()
	peer, ok := s.peers[id]
	if !ok {
		return ErrNotFound
	}
	peer.LastHandshakeAt = &t
	return nil
}
