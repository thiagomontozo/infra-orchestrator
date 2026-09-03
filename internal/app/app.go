package app

import (
	"context"
	"fmt"
	"github.com/thiagomontozo/infra-orchestrator/internal/adapters"
	"github.com/thiagomontozo/infra-orchestrator/internal/agent"
	"github.com/thiagomontozo/infra-orchestrator/internal/api"
	"github.com/thiagomontozo/infra-orchestrator/internal/auth"
	"github.com/thiagomontozo/infra-orchestrator/internal/cache"
	"github.com/thiagomontozo/infra-orchestrator/internal/config"
	"github.com/thiagomontozo/infra-orchestrator/internal/discovery"
	"github.com/thiagomontozo/infra-orchestrator/internal/domain"
	"github.com/thiagomontozo/infra-orchestrator/internal/events"
	"github.com/thiagomontozo/infra-orchestrator/internal/executor"
	"github.com/thiagomontozo/infra-orchestrator/internal/notifications"
	"github.com/thiagomontozo/infra-orchestrator/internal/observability"
	"github.com/thiagomontozo/infra-orchestrator/internal/operations"
	"github.com/thiagomontozo/infra-orchestrator/internal/provisioning"
	"github.com/thiagomontozo/infra-orchestrator/internal/scheduler"
	"github.com/thiagomontozo/infra-orchestrator/internal/secrets"
	"github.com/thiagomontozo/infra-orchestrator/internal/security"
	"github.com/thiagomontozo/infra-orchestrator/internal/store"
	"github.com/thiagomontozo/infra-orchestrator/internal/telemetry"
	"log/slog"
	"net/http"
	"os"
	"os/signal"
	"sync"
	"syscall"
	"time"
)

type Application struct {
	Config    config.Config
	DB        *store.DB
	API       *api.Server
	Engine    *operations.Engine
	Discovery *discovery.Service
	Agent     *agent.Runtime
	Redis     *cache.Redis
}

func Build(ctx context.Context, c config.Config) (*Application, error) {
	db, e := store.Open(ctx, c.DatabaseURL)
	if e != nil {
		return nil, e
	}
	failed := true
	defer func() {
		if failed {
			db.Pool.Close()
		}
	}()
	if e = db.Migrate(ctx); e != nil {
		return nil, e
	}
	cipher, e := security.NewCipher(c.EncryptionKey)
	if e != nil {
		return nil, e
	}
	network, e := security.NewNetworkPolicy(c.AllowedCIDRs)
	if e != nil {
		return nil, e
	}
	var secretProvider secrets.Provider = &secrets.Local{DB: db, Cipher: cipher}
	if c.SecretBackend == "vault" {
		if e = network.ValidateURL(c.VaultURL); e != nil {
			return nil, e
		}
		secretProvider = &secrets.Vault{URL: c.VaultURL, Token: c.VaultToken, Mount: config.Env("VAULT_MOUNT", "secret"), Client: network.Client(15 * time.Second)}
	} else if c.SecretBackend != "local" {
		return nil, fmt.Errorf("unsupported SECRET_BACKEND")
	}
	remote := &executor.SSH{Inventory: db, Secrets: secretProvider, Network: network, KnownHosts: c.KnownHosts, ConnectTimeout: c.SSHTimeout, CommandTimeout: c.CommandTimeout, Slots: make(chan struct{}, c.Concurrency*2)}
	registry := adapters.New(remote)
	registry["kubernetes-api"] = &adapters.KubernetesAPI{DB: db, Secrets: secretProvider, Network: network}
	registry["provisioning"] = &provisioning.Docker{API: remote, DB: db, Secrets: secretProvider, CLI: registry["docker"]}
	engine := &operations.Engine{DB: db, Adapters: registry, Secrets: secretProvider}
	disc := &discovery.Service{DB: db, Executor: remote, Adapters: registry}
	identity := auth.New(db, cipher, c)
	if c.LDAPURL != "" {
		identity.Providers["ldap"] = &auth.LDAP{Config: c}
	}
	ai := &agent.Runtime{DB: db, Secrets: secretProvider, Network: network, Engine: engine}
	server := &api.Server{Config: c, DB: db, Auth: identity, SSH: remote, Secrets: secretProvider, Engine: engine, Discovery: disc, Network: network, AI: ai}
	if c.Metrics {
		server.Metrics = telemetry.Handler(db)
	}
	app := &Application{Config: c, DB: db, API: server, Engine: engine, Discovery: disc, Agent: ai}
	if c.RedisURL != "" {
		app.Redis, e = cache.New(c.RedisURL)
		if e != nil {
			return nil, e
		}
		if e = app.Redis.Client.Ping(ctx).Err(); e != nil {
			return nil, e
		}
		server.Limiter = app.Redis
	}
	failed = false
	return app, nil
}
func Run(workerOnly bool) error {
	level := slog.LevelInfo
	if config.Env("LOG_LEVEL", "info") == "debug" {
		level = slog.LevelDebug
	}
	slog.SetDefault(slog.New(slog.NewJSONHandler(os.Stdout, &slog.HandlerOptions{Level: level})))
	cfg, e := config.Load()
	if e != nil {
		return e
	}
	ctx, stop := signal.NotifyContext(context.Background(), os.Interrupt, syscall.SIGTERM)
	defer stop()
	initCtx, cancel := context.WithTimeout(ctx, 30*time.Second)
	a, e := Build(initCtx, cfg)
	cancel()
	if e != nil {
		return e
	}
	defer a.DB.Pool.Close()
	if a.Redis != nil {
		defer a.Redis.Client.Close()
	}
	shutdownTracing, e := telemetry.Init(ctx, cfg.Name, cfg.OTEL)
	if e != nil {
		return e
	}
	defer func() {
		ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
		defer cancel()
		_ = shutdownTracing(ctx)
	}()
	var wg sync.WaitGroup
	start := func(fn func(context.Context)) { wg.Add(1); go func() { defer wg.Done(); fn(ctx) }() }
	if cfg.NATSURL != "" {
		bus, e := events.Connect(cfg.NATSURL)
		if e != nil {
			return e
		}
		defer bus.Close()
		start(func(ctx context.Context) { events.Relay(ctx, a.DB, bus) })
	}
	if workerOnly || cfg.WorkerEnabled {
		worker := &operations.Worker{Engine: a.Engine, Queue: &operations.PGQueue{DB: a.DB}, ID: domain.ID(), Concurrency: cfg.Concurrency}
		start(worker.Run)
		collector := &observability.Collector{DB: a.DB, Discovery: a.Discovery}
		start(collector.Run)
		start(a.Agent.Monitor)
		dispatcher := &notifications.Dispatcher{DB: a.DB, Network: a.API.Network, Secrets: a.API.Secrets}
		start(dispatcher.Run)
	}
	if !workerOnly {
		schedule := &scheduler.Scheduler{DB: a.DB, Engine: a.Engine}
		start(schedule.Run)
		server := &http.Server{Addr: cfg.Address, Handler: a.API.Handler(), ReadHeaderTimeout: 5 * time.Second, ReadTimeout: 30 * time.Second, IdleTimeout: 60 * time.Second, MaxHeaderBytes: 32 * 1024}
		errs := make(chan error, 1)
		go func() {
			slog.Info("server listening", "address", cfg.Address, "name", cfg.Name)
			errs <- server.ListenAndServe()
		}()
		select {
		case <-ctx.Done():
		case e = <-errs:
			if e != nil && e != http.ErrServerClosed {
				slog.Error("HTTP server failed", "error", e)
			}
			stop()
		}
		shutdownCtx, cancel := context.WithTimeout(context.Background(), 15*time.Second)
		_ = server.Shutdown(shutdownCtx)
		cancel()
	} else {
		<-ctx.Done()
	}
	stop()
	wg.Wait()
	if e != nil && e != http.ErrServerClosed {
		return e
	}
	return nil
}
