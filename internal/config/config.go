// Package config loads and validates runtime configuration for the template.
package config

import (
	"errors"
	"fmt"
	"strings"
	"time"

	"github.com/arcgolabs/configx"
)

type Config struct {
	HTTP HTTPConfig
	DB   DBConfig
	Auth AuthConfig
	KV   KVConfig
	RBAC RBACConfig
}

type HTTPConfig struct {
	Addr string
}

type DBConfig struct {
	// Driver supports: "sqlite", "mysql", "postgres"
	Driver string
	// DSN examples:
	// - sqlite:   file:rbac.db?_pragma=busy_timeout(5000)
	// - mysql:    user:pass@tcp(127.0.0.1:3306)/rbac?parseTime=true
	// - postgres: postgres://user:pass@localhost:5432/rbac?sslmode=disable
	DSN string
}

type AuthConfig struct {
	JWTSecret        string
	AccessTokenTTL   time.Duration
	Issuer           string
	Audience         string
	AllowInsecureDev bool

	// Sources controls which login sources are enabled for /auth/login.
	// Format: comma-separated list, e.g. "root,db".
	Sources string
	// RootUsername/RootPassword configure the static super-admin account when "root" source is enabled.
	RootUsername string
	RootPassword string

	// RefreshTokenTTL controls cookie refresh token lifetime.
	RefreshTokenTTL time.Duration

	// LoginRateLimit/LoginRateWindow limit auth login attempts by client+username key.
	LoginRateLimit  int
	LoginRateWindow time.Duration
	// RefreshRateLimit/RefreshRateWindow limit refresh attempts by client key.
	RefreshRateLimit  int
	RefreshRateWindow time.Duration
}

type RBACConfig struct {
	BootstrappedAdminUserID string
}

type KVConfig struct {
	Enabled bool
	// Driver: "valkey" (default) or "redis"
	Driver string
	// Addr: host:port
	Addr     string
	Password string
	DB       int
	// Prefix for keys, e.g. "arcgo:"
	Prefix string
	// DefaultTTL for cache entries.
	DefaultTTL time.Duration
}

// legacyRaw mirrors configx hierarchical keys (.env legacy names map via WithEnvSeparator).
type legacyRaw struct {
	HTTP struct {
		Addr string `mapstructure:"addr"`
	} `mapstructure:"http"`

	DB struct {
		Driver string `mapstructure:"driver"`
		DSN    string `mapstructure:"dsn"`
	} `mapstructure:"db"`

	JWT struct {
		Secret   string `mapstructure:"secret"`
		Issuer   string `mapstructure:"issuer"`
		Audience string `mapstructure:"audience"`
	} `mapstructure:"jwt"`

	Access struct {
		Token struct {
			TTL time.Duration `mapstructure:"ttl"`
		} `mapstructure:"token"`
	} `mapstructure:"access"`

	Refresh struct {
		Token struct {
			TTL time.Duration `mapstructure:"ttl"`
		} `mapstructure:"token"`
	} `mapstructure:"refresh"`

	KV struct {
		Enabled    bool          `mapstructure:"enabled"`
		Driver     string        `mapstructure:"driver"`
		Addr       string        `mapstructure:"addr"`
		Password   string        `mapstructure:"password"`
		DB         int           `mapstructure:"db"`
		Prefix     string        `mapstructure:"prefix"`
		DefaultTTL time.Duration `mapstructure:"default_ttl"`
	} `mapstructure:"kv"`

	Allow struct {
		Insecure struct {
			Dev bool `mapstructure:"dev"`
		} `mapstructure:"insecure"`
	} `mapstructure:"allow"`

	Auth struct {
		Sources string `mapstructure:"sources"`
		Root    struct {
			Username string `mapstructure:"username"`
			Password string `mapstructure:"password"`
		} `mapstructure:"root"`
		Login struct {
			Rate struct {
				Limit  int           `mapstructure:"limit"`
				Window time.Duration `mapstructure:"window"`
			} `mapstructure:"rate"`
		} `mapstructure:"login"`
		Refresh struct {
			Rate struct {
				Limit  int           `mapstructure:"limit"`
				Window time.Duration `mapstructure:"window"`
			} `mapstructure:"rate"`
		} `mapstructure:"refresh"`
	} `mapstructure:"auth"`

	Bootstrap struct {
		Admin struct {
			User struct {
				ID string `mapstructure:"id"`
			} `mapstructure:"user"`
		} `mapstructure:"admin"`
	} `mapstructure:"bootstrap"`
}

// Load loads typed config using configx (dotenv → file → env → args).
// This is intended to be called from a dix provider.
func Load() (Config, error) {
	// NOTE: configx env loader lowercases keys and replaces "_" with "."
	// (unless you set WithEnvSeparator("__")). This template keeps legacy flat env
	// var names (JWT_SECRET, ACCESS_TOKEN_TTL, BOOTSTRAP_ADMIN_USER_ID, ...) and
	// maps them through a raw hierarchical shape compatible with configx.
	raw, err := configx.LoadTErr[legacyRaw](
		// default order: dotenv → file → env → args
		// We keep files empty by default; callers can add configx.WithFiles(...) later.
		configx.WithDotenv(".env", ".env.local"),
		configx.WithIgnoreDotenvError(true),
		configx.WithValidateLevel(configx.ValidateLevelNone),
		configx.WithEnvPrefix(""),
		configx.WithEnvSeparator("_"),
		configx.WithDefaults(map[string]any{
			"http.addr":                ":8080",
			"db.driver":                "sqlite",
			"db.dsn":                   "file:rbac.db?_pragma=busy_timeout(5000)",
			"jwt.issuer":               "arcgo-rbac-template",
			"jwt.audience":             "arcgo",
			"access.token.ttl":         "30m",
			"refresh.token.ttl":        "168h",
			"allow.insecure.dev":       true,
			"auth.sources":             "root,db",
			"auth.root.username":       "root",
			"auth.root.password":       "root",
			"auth.login.rate.limit":    20,
			"auth.login.rate.window":   "1m",
			"auth.refresh.rate.limit":  60,
			"auth.refresh.rate.window": "1m",
			"bootstrap.admin.user.id":  "admin",
			"kv.enabled":               false,
			"kv.driver":                "valkey",
			"kv.addr":                  "127.0.0.1:6379",
			"kv.password":              "",
			"kv.db":                    0,
			"kv.prefix":                "arcgo:",
			"kv.default_ttl":           "30s",
		}),
	)
	if err != nil {
		return Config{}, err
	}

	return finalizeLoadedConfig(raw)
}

func finalizeLoadedConfig(raw legacyRaw) (Config, error) {
	cfg := buildConfigFromRaw(raw)

	compatMemorySQLite(&cfg)

	if err := ensureJWTSecret(&cfg); err != nil {
		return Config{}, err
	}
	if err := ensureNonEmptyDSN(&cfg); err != nil {
		return Config{}, err
	}
	return cfg, nil
}

func buildConfigFromRaw(raw legacyRaw) Config {
	return Config{
		HTTP: HTTPConfig{Addr: strings.TrimSpace(raw.HTTP.Addr)},
		DB: DBConfig{
			Driver: strings.TrimSpace(raw.DB.Driver),
			DSN:    strings.TrimSpace(raw.DB.DSN),
		},
		Auth: AuthConfig{
			JWTSecret:         strings.TrimSpace(raw.JWT.Secret),
			AccessTokenTTL:    raw.Access.Token.TTL,
			Issuer:            strings.TrimSpace(raw.JWT.Issuer),
			Audience:          strings.TrimSpace(raw.JWT.Audience),
			AllowInsecureDev:  raw.Allow.Insecure.Dev,
			Sources:           strings.TrimSpace(raw.Auth.Sources),
			RootUsername:      strings.TrimSpace(raw.Auth.Root.Username),
			RootPassword:      raw.Auth.Root.Password,
			RefreshTokenTTL:   raw.Refresh.Token.TTL,
			LoginRateLimit:    raw.Auth.Login.Rate.Limit,
			LoginRateWindow:   raw.Auth.Login.Rate.Window,
			RefreshRateLimit:  raw.Auth.Refresh.Rate.Limit,
			RefreshRateWindow: raw.Auth.Refresh.Rate.Window,
		},
		KV: KVConfig{
			Enabled:    raw.KV.Enabled,
			Driver:     strings.TrimSpace(raw.KV.Driver),
			Addr:       strings.TrimSpace(raw.KV.Addr),
			Password:   raw.KV.Password,
			DB:         raw.KV.DB,
			Prefix:     strings.TrimSpace(raw.KV.Prefix),
			DefaultTTL: raw.KV.DefaultTTL,
		},
		RBAC: RBACConfig{
			BootstrappedAdminUserID: strings.TrimSpace(raw.Bootstrap.Admin.User.ID),
		},
	}
}

func compatMemorySQLite(cfg *Config) {
	if !strings.EqualFold(cfg.DB.Driver, "memory") {
		return
	}
	cfg.DB.Driver = "sqlite"
	if strings.TrimSpace(cfg.DB.DSN) == "" {
		cfg.DB.DSN = "file::memory:?cache=shared"
	}
}

func ensureJWTSecret(cfg *Config) error {
	if cfg.Auth.JWTSecret != "" {
		return nil
	}
	if !cfg.Auth.AllowInsecureDev {
		return errors.New("JWT_SECRET is required when ALLOW_INSECURE_DEV=false")
	}
	cfg.Auth.JWTSecret = "dev-secret-change-me"
	return nil
}

func ensureNonEmptyDSN(cfg *Config) error {
	if cfg.DB.Driver == "memory" || strings.TrimSpace(cfg.DB.DSN) != "" {
		return nil
	}
	if cfg.DB.Driver == "sqlite" {
		cfg.DB.DSN = "file:rbac.db?_pragma=busy_timeout(5000)"
		return nil
	}
	return fmt.Errorf("DB_DSN is required when DB_DRIVER=%s", cfg.DB.Driver)
}

// FromEnv is kept for backward compatibility; it delegates to Load().
func FromEnv() (Config, error) {
	return Load()
}
