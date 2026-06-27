package main

import (
	"log/slog"
	"os"

	"github.com/lunarauthority/support-oidc-proxy/internal/proxy"
)

func main() {
	slog.SetDefault(slog.New(slog.NewJSONHandler(os.Stdout, nil)))

	cfg, err := proxy.ConfigFromEnv()
	if err != nil {
		slog.Error("config error", "err", err)
		os.Exit(1)
	}

	srv, err := proxy.New(cfg)
	if err != nil {
		slog.Error("server init failed", "err", err)
		os.Exit(1)
	}

	if err := srv.ListenAndServe(); err != nil {
		slog.Error("server exited", "err", err)
		os.Exit(1)
	}
}
