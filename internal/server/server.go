package server

import (
	"context"
	"crypto/subtle"
	"encoding/base64"
	"errors"
	"io"
	"log"
	"net"
	"net/http"
	"strings"
	"time"

	"github.com/gin-gonic/gin"
	"github.com/golang-jwt/jwt/v5"
	"github.com/google/uuid"
	"golang.zx2c4.com/wireguard/wgctrl/wgtypes"

	"github.com/example/wireguard-gateway/internal/peers"
	templater "github.com/example/wireguard-gateway/internal/template"
	"github.com/example/wireguard-gateway/internal/wg"
)

// WireguardManager defines the subset of wg.Manager used by the server.
type WireguardManager interface {
	AddPeer(publicKey wgtypes.Key, preshared *wgtypes.Key, allowedIPs []net.IPNet) error
	RemovePeer(publicKey wgtypes.Key) error
	Handshakes() (map[string]time.Time, error)
}

// Options configures the HTTP server.
type Options struct {
	ListenAddr             string
	Interface              string
	Endpoint               string
	TrustProxyLoopbackOnly bool
	Renderer               *templater.Renderer
	PeerStore              *peers.Store
	Manager                WireguardManager
	UsePresharedKey        bool
	BasicAuthUsername      string
	BasicAuthPassword      string
	JWTSecret              string
}

// Server wraps the Gin engine and HTTP server.
type Server struct {
	opts   Options
	engine *gin.Engine
	srv    *http.Server
}

// New constructs a new Server.
func New(opts Options) (*Server, error) {
	if opts.Renderer == nil || opts.PeerStore == nil || opts.Manager == nil {
		return nil, errors.New("missing dependencies")
	}

	engine := gin.New()
	engine.Use(gin.Recovery())
	engine.Use(requestLogger())

	if opts.TrustProxyLoopbackOnly {
		if err := engine.SetTrustedProxies([]string{"127.0.0.1", "::1"}); err != nil {
			return nil, err
		}
	} else {
		if err := engine.SetTrustedProxies(nil); err != nil {
			return nil, err
		}
	}

	if opts.BasicAuthUsername == "" || opts.BasicAuthPassword == "" {
		return nil, errors.New("basic auth credentials are required")
	}
	if opts.JWTSecret == "" {
		return nil, errors.New("jwt secret is required")
	}

	s := &Server{opts: opts, engine: engine}

	basicAuth := requireBasicAuth(opts.BasicAuthUsername, opts.BasicAuthPassword)
	jwtAuth := requireJWTAuth(opts.JWTSecret)

	engine.GET("/healthz", basicAuth, s.handleHealthz)
	engine.POST("/peer", jwtAuth, s.handleCreatePeer)
	engine.DELETE("/peer/:id", basicAuth, s.handleDeletePeer)
	engine.POST("/admin/reload-template", basicAuth, s.handleReloadTemplate)

	s.srv = &http.Server{
		Addr:    opts.ListenAddr,
		Handler: engine,
	}

	return s, nil
}

// Run starts the HTTP server and blocks until it stops.
func (s *Server) Run() error {
	log.Printf("listening on %s", s.opts.ListenAddr)
	return s.srv.ListenAndServe()
}

// Shutdown gracefully stops the HTTP server.
func (s *Server) Shutdown(ctx context.Context) error {
	return s.srv.Shutdown(ctx)
}

// Handler exposes the underlying HTTP handler (primarily for tests).
func (s *Server) Handler() http.Handler {
	return s.engine
}

func (s *Server) handleHealthz(c *gin.Context) {
	c.JSON(http.StatusOK, gin.H{"ok": true})
}

func (s *Server) handleCreatePeer(c *gin.Context) {
	clientIP := net.ParseIP(c.ClientIP())
	if clientIP == nil {
		c.JSON(http.StatusBadRequest, gin.H{"error": "invalid client ip"})
		return
	}
	if clientIP.To4() == nil {
		c.JSON(http.StatusForbidden, gin.H{"error": "ipv6 not allowed"})
		return
	}

	var req createPeerRequest
	if err := c.ShouldBindJSON(&req); err != nil {
		if !errors.Is(err, io.EOF) {
			c.JSON(http.StatusBadRequest, gin.H{"error": "invalid request body"})
			return
		}
	}

	peerID := uuid.NewString()

	privateKey, err := wgtypes.GeneratePrivateKey()
	if err != nil {
		log.Printf("generate private key: %v", err)
		c.JSON(http.StatusInternalServerError, gin.H{"error": "generate key"})
		return
	}
	publicKey := privateKey.PublicKey()

	var preshared *wgtypes.Key
	var presharedString string
	if s.opts.UsePresharedKey {
		key, err := wgtypes.GenerateKey()
		if err != nil {
			log.Printf("generate preshared key: %v", err)
			c.JSON(http.StatusInternalServerError, gin.H{"error": "generate preshared key"})
			return
		}
		preshared = &key
		presharedString = key.String()
	}

	allowedNet, err := wg.AllowedIPNet(clientIP)
	if err != nil {
		c.JSON(http.StatusInternalServerError, gin.H{"error": "build allowed ip"})
		return
	}

	if err := s.opts.Manager.AddPeer(publicKey, preshared, []net.IPNet{allowedNet}); err != nil {
		log.Printf("add peer: %v", err)
		c.JSON(http.StatusInternalServerError, gin.H{"error": "add peer"})
		return
	}

	allowedCIDR := allowedNet.String()
	now := time.Now().UTC()
	peer := &peers.Peer{
		ID:           peerID,
		PublicKey:    publicKey.String(),
		PrivateKey:   privateKey.String(),
		PresharedKey: presharedString,
		ClientIPv4:   clientIP,
		AllowedCIDR:  allowedCIDR,
		Interface:    s.opts.Interface,
		CreatedAt:    now,
	}
	s.opts.PeerStore.Add(peer)

	data := map[string]any{
		"PeerID":           peerID,
		"Interface":        s.opts.Interface,
		"ClientIPv4":       clientIP.String(),
		"PeerPublicKey":    publicKey.String(),
		"PeerPrivateKey":   privateKey.String(),
		"PresharedKey":     presharedString,
		"AllowedIPs":       allowedCIDR,
		"Endpoint":         s.opts.Endpoint,
		"CreatedAt":        now,
		"CreatedAtRFC3339": now.Format(time.RFC3339),
		"Note":             req.Note,
	}

	rendered, err := s.opts.Renderer.Render(data)
	if err != nil {
		log.Printf("render template: %v", err)
		c.JSON(http.StatusInternalServerError, gin.H{"error": "template render failed"})
		return
	}

	c.Data(http.StatusCreated, "application/json", []byte(rendered))
}

func (s *Server) handleDeletePeer(c *gin.Context) {
	id := c.Param("id")
	peer, err := s.opts.PeerStore.Delete(id)
	if err != nil {
		if errors.Is(err, peers.ErrNotFound) {
			c.JSON(http.StatusNotFound, gin.H{"error": "peer not found"})
			return
		}
		c.JSON(http.StatusInternalServerError, gin.H{"error": "delete peer"})
		return
	}

	key, err := wgtypes.ParseKey(peer.PublicKey)
	if err != nil {
		c.JSON(http.StatusInternalServerError, gin.H{"error": "parse public key"})
		return
	}

	if err := s.opts.Manager.RemovePeer(key); err != nil {
		log.Printf("remove peer: %v", err)
		c.JSON(http.StatusInternalServerError, gin.H{"error": "remove peer"})
		return
	}

	c.Status(http.StatusNoContent)
}

func (s *Server) handleReloadTemplate(c *gin.Context) {
	if err := s.opts.Renderer.Reload(); err != nil {
		c.JSON(http.StatusInternalServerError, gin.H{"error": err.Error()})
		return
	}
	c.Status(http.StatusNoContent)
}

func requestLogger() gin.HandlerFunc {
	return func(c *gin.Context) {
		start := time.Now()
		c.Next()
		latency := time.Since(start)
		status := c.Writer.Status()
		log.Printf("%s %s -> %d (%s)", c.Request.Method, c.Request.URL.Path, status, latency)
	}
}

type createPeerRequest struct {
	Note string `json:"note"`
}

func requireBasicAuth(username, password string) gin.HandlerFunc {
	expected := username + ":" + password

	return func(c *gin.Context) {
		header := c.GetHeader("Authorization")
		const prefix = "Basic "
		if !strings.HasPrefix(header, prefix) {
			unauthorizedBasic(c)
			return
		}

		decoded, err := base64.StdEncoding.DecodeString(header[len(prefix):])
		if err != nil {
			unauthorizedBasic(c)
			return
		}

		if subtle.ConstantTimeCompare(decoded, []byte(expected)) != 1 {
			unauthorizedBasic(c)
			return
		}

		c.Next()
	}
}

func unauthorizedBasic(c *gin.Context) {
	c.Header("WWW-Authenticate", "Basic realm=\"restricted\"")
	c.JSON(http.StatusUnauthorized, gin.H{"error": "unauthorized"})
	c.Abort()
}

func requireJWTAuth(secret string) gin.HandlerFunc {
	return func(c *gin.Context) {
		header := c.GetHeader("Authorization")
		const prefix = "Bearer "
		if !strings.HasPrefix(header, prefix) {
			c.JSON(http.StatusUnauthorized, gin.H{"error": "unauthorized"})
			c.Abort()
			return
		}

		tokenStr := header[len(prefix):]
		token, err := jwt.Parse(tokenStr, func(t *jwt.Token) (interface{}, error) {
			if t.Method.Alg() != jwt.SigningMethodHS256.Alg() {
				return nil, errors.New("unexpected signing method")
			}
			return []byte(secret), nil
		})
		if err != nil || !token.Valid {
			c.JSON(http.StatusUnauthorized, gin.H{"error": "unauthorized"})
			c.Abort()
			return
		}

		c.Next()
	}
}
