package main

import (
	"context"
	"log"
	"net/http"
	"os/signal"
	"syscall"
	"time"

	"github.com/gin-gonic/gin"
	"github.com/kelseyhightower/envconfig"

	"github.com/example/wireguard-gateway/internal/gc"
	"github.com/example/wireguard-gateway/internal/peers"
	"github.com/example/wireguard-gateway/internal/server"
	templater "github.com/example/wireguard-gateway/internal/template"
	"github.com/example/wireguard-gateway/internal/wg"
)

// Config holds runtime configuration loaded from environment variables.
type Config struct {
	ListenAddr                 string `split_words:"true" default:":8080"`
	WGInterface                string `split_words:"true" required:"true"`
	WGEndpoint                 string `split_words:"true" required:"true"`
	PersistentKeepaliveSeconds int    `split_words:"true" default:"0"`
	JSONTemplatePath           string `split_words:"true" required:"true"`
	AuthBearerToken            string `split_words:"true"`
	TrustProxyLoopbackOnly     bool   `split_words:"true" default:"true"`
	LogLevel                   string `split_words:"true" default:"info"`
	UsePresharedKey            bool   `split_words:"true" default:"false"`
}

func main() {
	var cfg Config
	if err := envconfig.Process("", &cfg); err != nil {
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

	srv, err := server.New(server.Options{
		ListenAddr:             cfg.ListenAddr,
		Interface:              cfg.WGInterface,
		Endpoint:               cfg.WGEndpoint,
		AuthBearerToken:        cfg.AuthBearerToken,
		TrustProxyLoopbackOnly: cfg.TrustProxyLoopbackOnly,
		Renderer:               renderer,
		PeerStore:              peerStore,
		Manager:                wgManager,
		UsePresharedKey:        cfg.UsePresharedKey,
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
