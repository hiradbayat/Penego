package config

import (
	"bufio"
	"fmt"
	"os"
	"strconv"
	"strings"
)

type Config struct {
	DatabaseDSN     string
	ListenAddr      string
	AdminPassword   string
	SessionSecret   string
	MaxHosts        int
	MaxPorts        int
	DefaultHostConc int
	DefaultPortConc int
	RateLimitPerMin int
	AuthDisabled    bool
}

func Load() (*Config, error) {
	_ = loadDotEnv(".env")

	cfg := &Config{
		DatabaseDSN:     env("DATABASE_DSN", ""),
		ListenAddr:      env("LISTEN_ADDR", "127.0.0.1:8585"),
		AdminPassword:   env("ADMIN_PASSWORD", "penego"),
		SessionSecret:   env("SESSION_SECRET", "change-me-penego-session-secret"),
		MaxHosts:        envInt("MAX_HOSTS", 1024),
		MaxPorts:        envInt("MAX_PORTS", 4096),
		DefaultHostConc: envInt("DEFAULT_HOST_CONCURRENCY", 100),
		DefaultPortConc: envInt("DEFAULT_PORT_CONCURRENCY", 100),
		RateLimitPerMin: envInt("RATE_LIMIT_PER_MIN", 60),
		AuthDisabled:    env("AUTH_DISABLED", "false") == "true",
	}

	if cfg.DatabaseDSN == "" {
		return nil, fmt.Errorf("DATABASE_DSN is required (see .env.example)")
	}
	return cfg, nil
}

func env(key, fallback string) string {
	if v := os.Getenv(key); v != "" {
		return v
	}
	return fallback
}

func envInt(key string, fallback int) int {
	v := os.Getenv(key)
	if v == "" {
		return fallback
	}
	n, err := strconv.Atoi(v)
	if err != nil {
		return fallback
	}
	return n
}

func loadDotEnv(path string) error {
	f, err := os.Open(path)
	if err != nil {
		return err
	}
	defer f.Close()

	sc := bufio.NewScanner(f)
	for sc.Scan() {
		line := strings.TrimSpace(sc.Text())
		if line == "" || strings.HasPrefix(line, "#") {
			continue
		}
		key, val, ok := strings.Cut(line, "=")
		if !ok {
			continue
		}
		key = strings.TrimSpace(key)
		val = strings.TrimSpace(val)
		val = strings.Trim(val, `"'`)
		if os.Getenv(key) == "" {
			_ = os.Setenv(key, val)
		}
	}
	return sc.Err()
}
