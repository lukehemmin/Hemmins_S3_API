package main

import (
	"flag"
	"fmt"
	"log"
	"net/http"
	"os"
	"strings"

	"github.com/lukehemmin/hemmins-s3-api/internal/bootstrap"
	"github.com/lukehemmin/hemmins-s3-api/internal/config"
	"github.com/lukehemmin/hemmins-s3-api/internal/health"
	s3api "github.com/lukehemmin/hemmins-s3-api/internal/http/s3"
	uiapi "github.com/lukehemmin/hemmins-s3-api/internal/http/ui"
	"github.com/lukehemmin/hemmins-s3-api/internal/metadata"
)

func main() {
	var configFile string
	flag.StringVar(&configFile, "config", "", "path to config file (overrides HEMMINS_CONFIG_FILE and ./config.yaml)")
	flag.Parse()

	cfg, bootstrapCfg, err := config.Load(configFile)
	if err != nil {
		fmt.Fprintf(os.Stderr, "fatal: %v\n", err)
		os.Exit(1)
	}

	if err := config.Validate(cfg); err != nil {
		fmt.Fprintf(os.Stderr, "fatal: %v\n", err)
		os.Exit(1)
	}

	if err := config.InitializePaths(cfg); err != nil {
		fmt.Fprintf(os.Stderr, "fatal: %v\n", err)
		os.Exit(1)
	}

	if cfg.ConfigFilePath != "" {
		log.Printf("config: loaded from %s", cfg.ConfigFilePath)
	} else {
		log.Printf("config: no config file found, using defaults and environment variables")
	}

	// Open metadata database (creates schema on first run).
	db, err := metadata.Open(cfg.Paths.MetaDB)
	if err != nil {
		fmt.Fprintf(os.Stderr, "fatal: opening metadata DB: %v\n", err)
		os.Exit(1)
	}
	defer db.Close()

	// Startup recovery: integrity check, stale temp cleanup, corrupt blob scan.
	// OrphanGracePeriod comes from gc.orphan_grace_period per configuration-model.md section 5.8.
	recoveryCfg := metadata.RecoveryConfig{
		TempRoot:          cfg.Paths.TempRoot,
		ObjectRoot:        cfg.Paths.ObjectRoot,
		MultipartRoot:     cfg.Paths.MultipartRoot,
		OrphanGracePeriod: cfg.GC.OrphanGracePeriod.Duration,
	}
	if err := metadata.StartupRecovery(db, recoveryCfg); err != nil {
		fmt.Fprintf(os.Stderr, "fatal: startup recovery: %v\n", err)
		os.Exit(1)
	}

	state := health.NewState()

	// Determine the database initialization state and act accordingly.
	// Per security-model.md section 3.1 and configuration-model.md section 2.2:
	// bootstrap input is consumed ONLY when the DB is in the empty state.
	dbState, err := db.BootstrapState()
	if err != nil {
		fmt.Fprintf(os.Stderr, "fatal: checking bootstrap state: %v\n", err)
		os.Exit(1)
	}
	log.Printf("db: initialization state = %s", dbState)

	switch dbState {

	case metadata.DBStateBootstrapped:
		// Database is fully initialized. Bootstrap env vars are ignored with a warning.
		// Per configuration-model.md section 2.2.
		if bootstrapCfg.HasValues {
			log.Printf("bootstrap: database is already bootstrapped; HEMMINS_BOOTSTRAP_* env vars are ignored")
		}
		state.SetReady(true)

	case metadata.DBStateEmpty:
		// Empty database. Apply bootstrap credentials if provided.
		if bootstrapCfg.HasValues {
			if err := bootstrap.Apply(db, bootstrapCfg, cfg.Auth.MasterKey); err != nil {
				fmt.Fprintf(os.Stderr, "fatal: applying bootstrap credentials: %v\n", err)
				os.Exit(1)
			}
			// Verify the DB is now bootstrapped after application.
			newState, err := db.BootstrapState()
			if err != nil {
				fmt.Fprintf(os.Stderr, "fatal: verifying bootstrap state after apply: %v\n", err)
				os.Exit(1)
			}
			if newState != metadata.DBStateBootstrapped {
				fmt.Fprintf(os.Stderr, "fatal: bootstrap appeared to succeed but DB state is %s\n", newState)
				os.Exit(1)
			}
			state.SetReady(true)
		} else {
			log.Printf("setup-required: database is empty; provide all HEMMINS_BOOTSTRAP_* env vars and restart")
			// HTTP server starts (liveness probe passes) but readyz returns 503.
			state.SetReady(false)
		}

	case metadata.DBStatePartial:
		// Partial initialization is an inconsistent state requiring operator intervention.
		// Per security-model.md section 3.1: bootstrap is only for empty DBs.
		// Do NOT attempt to apply bootstrap credentials here.
		log.Printf("partial-init: database is in an inconsistent partial initialization state")
		log.Printf("partial-init: some credential records exist but bootstrap is not complete")
		log.Printf("partial-init: operator intervention is required; inspect ui_users and access_keys tables")
		if bootstrapCfg.HasValues {
			log.Printf("partial-init: HEMMINS_BOOTSTRAP_* credentials were provided but are NOT applied in partial state")
		}
		// Remain not-ready until the operator resolves the inconsistency.
		state.SetReady(false)
	}

	// Build S3 API server and attach readiness gating.
	// Per product-spec.md section 8.4: S3 API must not be served in setup-required state.
	s3srv := s3api.NewServer(db, cfg.S3.Region, cfg.Auth.MasterKey)
	s3srv.SetStoragePaths(cfg.Paths.TempRoot, cfg.Paths.ObjectRoot)
	s3srv.SetMultipartRoot(cfg.Paths.MultipartRoot)
	s3srv.SetMultipartExpiry(cfg.GC.MultipartExpiry.Duration)
	s3srv.SetReady(state.IsReady)

	mux := http.NewServeMux()
	mux.HandleFunc("/healthz", health.HealthzHandler)
	mux.HandleFunc("/readyz", health.ReadyzHandler(state))

	// UI session API routes.
	// enable_ui=false policy: register a 404 handler so /ui/ never reaches the S3 handler.
	// enable_ui=true policy: register the full session auth API at /ui/.
	// Per configuration-model.md section 5.2: server.enable_ui controls UI availability.
	// Per security-model.md section 7: Secure cookie when public_endpoint is https://.
	if cfg.Server.EnableUI {
		secureCookie := strings.HasPrefix(cfg.Server.PublicEndpoint, "https://")
		uiStore := uiapi.NewSessionStore(
			cfg.UI.SessionTTL.Duration,
			cfg.UI.SessionIdleTTL.Duration,
		)
		uiSrv := uiapi.NewServer(db, uiStore, secureCookie)
		mux.Handle("/ui/", uiapi.WithReadinessGate(state.IsReady, uiSrv.Handler()))
		log.Printf("ui: session API enabled (secure_cookie=%v)", secureCookie)
	} else {
		log.Printf("ui: server.enable_ui=false; /ui/ routes return 404")
		mux.HandleFunc("/ui/", func(w http.ResponseWriter, r *http.Request) {
			http.NotFound(w, r)
		})
	}

	// S3 service root: registered last so /healthz, /readyz, and /ui/ take precedence.
	mux.Handle("/", s3srv.Handler())

	log.Printf("hemmins-s3: listening on %s", cfg.Server.Listen)
	if err := http.ListenAndServe(cfg.Server.Listen, mux); err != nil {
		fmt.Fprintf(os.Stderr, "fatal: server error: %v\n", err)
		os.Exit(1)
	}
}
