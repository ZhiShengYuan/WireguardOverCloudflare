package wg

import (
	"fmt"
	"net"
	"time"

	"golang.zx2c4.com/wireguard/wgctrl"
	"golang.zx2c4.com/wireguard/wgctrl/wgtypes"
)

// Manager provides operations to manage WireGuard peers on an interface.
type Manager struct {
	client    *wgctrl.Client
	iface     string
	keepalive *time.Duration
}

// NewManager creates a Manager for the given interface name.
func NewManager(iface string, keepaliveSeconds int) (*Manager, error) {
	client, err := wgctrl.New()
	if err != nil {
		return nil, fmt.Errorf("create wgctrl client: %w", err)
	}
	var keepalive *time.Duration
	if keepaliveSeconds > 0 {
		d := time.Duration(keepaliveSeconds) * time.Second
		keepalive = &d
	}
	return &Manager{client: client, iface: iface, keepalive: keepalive}, nil
}

// Close releases underlying resources.
func (m *Manager) Close() error {
	if m.client != nil {
		m.client.Close()
	}
	return nil
}

// VerifyInterface ensures the configured interface exists.
func (m *Manager) VerifyInterface() error {
	if _, err := m.client.Device(m.iface); err != nil {
		return fmt.Errorf("load device %s: %w", m.iface, err)
	}
	return nil
}

// AddPeer adds a peer to the WireGuard device.
func (m *Manager) AddPeer(publicKey wgtypes.Key, preshared *wgtypes.Key, allowedIPs []net.IPNet) error {
	cfg := wgtypes.Config{
		Peers: []wgtypes.PeerConfig{{
			PublicKey:                   publicKey,
			ReplaceAllowedIPs:           true,
			AllowedIPs:                  allowedIPs,
			PresharedKey:                preshared,
			PersistentKeepaliveInterval: m.keepalive,
		}},
	}
	if err := m.client.ConfigureDevice(m.iface, cfg); err != nil {
		return fmt.Errorf("configure device: %w", err)
	}
	return nil
}

// RemovePeer removes a peer by its public key.
func (m *Manager) RemovePeer(publicKey wgtypes.Key) error {
	cfg := wgtypes.Config{
		Peers: []wgtypes.PeerConfig{{
			PublicKey: publicKey,
			Remove:    true,
		}},
	}
	if err := m.client.ConfigureDevice(m.iface, cfg); err != nil {
		return fmt.Errorf("remove peer: %w", err)
	}
	return nil
}

// Handshakes returns the last handshake times for peers keyed by their public key string.
func (m *Manager) Handshakes() (map[string]time.Time, error) {
	device, err := m.client.Device(m.iface)
	if err != nil {
		return nil, fmt.Errorf("load device: %w", err)
	}
	result := make(map[string]time.Time, len(device.Peers))
	for _, peer := range device.Peers {
		if peer.PublicKey != (wgtypes.Key{}) {
			result[peer.PublicKey.String()] = peer.LastHandshakeTime
		}
	}
	return result, nil
}

// Interface returns the managed interface name.
func (m *Manager) Interface() string {
	return m.iface
}

// AllowedIPNet constructs a /32 network for the provided IPv4 address.
func AllowedIPNet(ip net.IP) (net.IPNet, error) {
	if ip.To4() == nil {
		return net.IPNet{}, fmt.Errorf("not an ipv4 address: %s", ip)
	}
	return net.IPNet{IP: ip, Mask: net.CIDRMask(32, 32)}, nil
}
