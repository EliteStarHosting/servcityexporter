// Command servcityexporter polls the ServCity User API
// (https://servcity.org/uapi/docs) and exposes the results as Prometheus
// metrics on /metrics.
package main

import (
	"context"
	"log/slog"
	"net/http"
	"os"
	"os/signal"
	"syscall"
	"time"

	"github.com/prometheus/client_golang/prometheus"
	"github.com/prometheus/client_golang/prometheus/promhttp"

	"github.com/elitestarhosting/servcityexporter/internal/config"
	"github.com/elitestarhosting/servcityexporter/internal/poller"
	"github.com/elitestarhosting/servcityexporter/internal/servcity"
	"github.com/elitestarhosting/servcityexporter/internal/store"
)

// version is overridden at build time via -ldflags "-X main.version=...".
var version = "dev"

const indexPage = `<!doctype html>
<html>
<head><title>ServCity Exporter</title></head>
<body>
<h1>ServCity Prometheus Exporter</h1>
<p><a href="/metrics">Metrics</a></p>
</body>
</html>
`

func main() {
	log := slog.New(slog.NewJSONHandler(os.Stdout, nil))

	cfg, err := config.Load()
	if err != nil {
		log.Error("invalid configuration", "error", err)
		os.Exit(1)
	}

	client := servcity.NewClient(cfg.APIBaseURL, cfg.APIKeyID, cfg.APIKeySecret, cfg.RequestTimeout)
	st := store.New()
	st.Set(store.Point{
		Name:   "servcity_exporter_build_info",
		Help:   "Static build info for the exporter; value is always 1.",
		Type:   prometheus.GaugeValue,
		Labels: map[string]string{"version": version},
		Value:  1,
	})

	reg := prometheus.NewRegistry()
	reg.MustRegister(st)

	ctx, stop := signal.NotifyContext(context.Background(), os.Interrupt, syscall.SIGTERM)
	defer stop()

	p := poller.New(client, st, log, cfg.FastInterval, cfg.SlowInterval)
	go p.Run(ctx)

	mux := http.NewServeMux()
	mux.Handle("/metrics", promhttp.HandlerFor(reg, promhttp.HandlerOpts{
		ErrorHandling: promhttp.ContinueOnError,
	}))
	mux.HandleFunc("/healthz", func(w http.ResponseWriter, _ *http.Request) {
		w.WriteHeader(http.StatusOK)
		_, _ = w.Write([]byte("ok"))
	})
	mux.HandleFunc("/", func(w http.ResponseWriter, r *http.Request) {
		if r.URL.Path != "/" {
			http.NotFound(w, r)
			return
		}
		w.Header().Set("Content-Type", "text/html; charset=utf-8")
		_, _ = w.Write([]byte(indexPage))
	})

	srv := &http.Server{
		Addr:              cfg.ListenAddr,
		Handler:           mux,
		ReadHeaderTimeout: 5 * time.Second,
	}

	go func() {
		<-ctx.Done()
		shutdownCtx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
		defer cancel()
		if err := srv.Shutdown(shutdownCtx); err != nil {
			log.Error("http server shutdown error", "error", err)
		}
	}()

	log.Info("servcity exporter starting",
		"version", version,
		"listen_addr", cfg.ListenAddr,
		"api_base_url", cfg.APIBaseURL,
		"poll_interval", cfg.FastInterval.String(),
		"discovery_interval", cfg.SlowInterval.String(),
	)
	if err := srv.ListenAndServe(); err != nil && err != http.ErrServerClosed {
		log.Error("http server error", "error", err)
		os.Exit(1)
	}
}
