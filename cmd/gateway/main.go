package main

import (
	"context"
	"encoding/json"
	"errors"
	"flag"
	"fmt"
	"log"
	"net/http"
	"os"
	"os/signal"
	"syscall"
	"time"

	"github.com/gin-gonic/gin"

	"github.com/example/wireguard-gateway/internal/gc"
	"github.com/example/wireguard-gateway/internal/peers"
	"github.com/example/wireguard-gateway/internal/server"
	templater "github.com/example/wireguard-gateway/internal/template"
	"github.com/example/wireguard-gateway/internal/wg"
)

// AuthConfig holds authentication settings.
type AuthConfig struct {
	Basic BasicAuthConfig `json:"basic"`
	JWT   JWTConfig       `json:"jwt"`
}

// BasicAuthConfig describes HTTP basic authentication credentials.
type BasicAuthConfig struct {
	Username string `json:"username"`
	Password string `json:"password"`
}

// JWTConfig describes JWT validation settings.
type JWTConfig struct {
	Secret string `json:"secret"`
}

// Config holds runtime configuration loaded from a JSON file.
type Config struct {
	ListenAddr                 string     `json:"listen_addr"`
	WGInterface                string     `json:"wg_interface"`
	WGEndpoint                 string     `json:"wg_endpoint"`
	PersistentKeepaliveSeconds int        `json:"persistent_keepalive_seconds"`
	JSONTemplatePath           string     `json:"json_template_path"`
	TrustProxyLoopbackOnly     *bool      `json:"trust_proxy_loopback_only"`
	LogLevel                   string     `json:"log_level"`
	UsePresharedKey            bool       `json:"use_preshared_key"`
	Auth                       AuthConfig `json:"auth"`
}

func loadConfig(path string) (Config, error) {
	file, err := os.Open(path)
	if err != nil {
		return Config{}, fmt.Errorf("open config: %w", err)
	}
	defer file.Close()

	var cfg Config
	decoder := json.NewDecoder(file)
	decoder.DisallowUnknownFields()
	if err := decoder.Decode(&cfg); err != nil {
		return Config{}, fmt.Errorf("decode config: %w", err)
	}

	if cfg.ListenAddr == "" {
		cfg.ListenAddr = ":8080"
	}
	if cfg.LogLevel == "" {
		cfg.LogLevel = "info"
	}

	if cfg.WGInterface == "" {
		return Config{}, errors.New("wg_interface is required")
	}
	if cfg.WGEndpoint == "" {
		return Config{}, errors.New("wg_endpoint is required")
	}
	if cfg.JSONTemplatePath == "" {
		return Config{}, errors.New("json_template_path is required")
	}
	if cfg.Auth.Basic.Username == "" || cfg.Auth.Basic.Password == "" {
		return Config{}, errors.New("basic auth credentials are required")
	}
	if cfg.Auth.JWT.Secret == "" {
		return Config{}, errors.New("jwt secret is required")
	}

	return cfg, nil
}

func main() {
	configPath := flag.String("config", "config.json", "path to configuration file")
	flag.Parse()

	cfg, err := loadConfig(*configPath)
	if err != nil {
		log.Fatalf("failed to load configuration: %v", err)
	}

	if cfg.LogLevel == "release" {
		gin.SetMode(gin.ReleaseMode)
	}

	renderer, err := templater.NewRenderer(cfg.JSONTemplatePath)
	if err != nil {
		log.Fatalf("failed to load template: %v", err)
	}

	wgManager, err := wg.NewManager(cfg.WGInterface, cfg.PersistentKeepaliveSeconds)
	if err != nil {
		log.Fatalf("failed to create wireguard manager: %v", err)
	}
	defer wgManager.Close()

	if err := wgManager.VerifyInterface(); err != nil {
		log.Fatalf("wireguard interface check failed: %v", err)
	}

	peerStore := peers.NewStore()

	trustProxy := true
	if cfg.TrustProxyLoopbackOnly != nil {
		trustProxy = *cfg.TrustProxyLoopbackOnly
	}

	srv, err := server.New(server.Options{
		ListenAddr:             cfg.ListenAddr,
		Interface:              cfg.WGInterface,
		Endpoint:               cfg.WGEndpoint,
		TrustProxyLoopbackOnly: trustProxy,
		Renderer:               renderer,
		PeerStore:              peerStore,
		Manager:                wgManager,
		UsePresharedKey:        cfg.UsePresharedKey,
		BasicAuthUsername:      cfg.Auth.Basic.Username,
		BasicAuthPassword:      cfg.Auth.Basic.Password,
		JWTSecret:              cfg.Auth.JWT.Secret,
	})
	if err != nil {
		log.Fatalf("failed to initialize server: %v", err)
	}

	ctx, stop := signal.NotifyContext(context.Background(), syscall.SIGINT, syscall.SIGTERM)
	defer stop()

	gcRunner := gc.New(gc.Options{
		Interval:          time.Minute,
		Store:             peerStore,
		Manager:           wgManager,
		Interface:         cfg.WGInterface,
		Logger:            log.Default(),
		NeverConnectedTTL: 10 * time.Minute,
		StaleHandshakeTTL: 24 * time.Hour,
	})

	go gcRunner.Run(ctx)

	serverErr := make(chan error, 1)
	go func() {
		serverErr <- srv.Run()
	}()

	select {
	case <-ctx.Done():
		log.Println("shutdown signal received")
	case err := <-serverErr:
		if err != nil && err != http.ErrServerClosed {
			log.Printf("server error: %v", err)
		}
	}

	shutdownCtx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
	defer cancel()

	if err := srv.Shutdown(shutdownCtx); err != nil {
		log.Printf("graceful shutdown failed: %v", err)
	}

	log.Println("gateway stopped")
}
