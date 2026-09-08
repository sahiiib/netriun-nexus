// Command nexus starts the Netriun Nexus service and background collector.
package main

import (
	"context"
	"errors"
	"github.com/netriun/nexus/internal/app"
	"log/slog"
	"net/http"
	"os"
	"os/signal"
	"syscall"
	"time"
)

func main() {
	slog.SetDefault(slog.New(slog.NewJSONHandler(os.Stdout, nil)))
	if err := run(); err != nil {
		slog.Error("server stopped", "error", err)
		os.Exit(1)
	}
}
func run() error {
	ctx, stop := signal.NotifyContext(context.Background(), os.Interrupt, syscall.SIGTERM)
	defer stop()
	startup, cancel := context.WithTimeout(ctx, 30*time.Second)
	a, err := app.New(startup)
	cancel()
	if err != nil {
		return err
	}
	defer a.Close()
	addr := os.Getenv("HTTP_ADDR")
	if addr == "" {
		addr = ":8080"
	}
	srv := &http.Server{Addr: addr, Handler: a.Handler(), ReadHeaderTimeout: 5 * time.Second, ReadTimeout: 15 * time.Second, WriteTimeout: 60 * time.Second, IdleTimeout: 60 * time.Second}
	workerDone := make(chan struct{})
	go func() { defer close(workerDone); a.Scheduler(ctx) }()
	serverErr := make(chan error, 1)
	go func() { slog.Info("Netriun Nexus listening", "address", addr); serverErr <- srv.ListenAndServe() }()
	select {
	case <-ctx.Done():
	case err = <-serverErr:
		stop()
	}
	shutdown, c := context.WithTimeout(context.Background(), 15*time.Second)
	defer c()
	srv.Shutdown(shutdown)
	<-workerDone
	if errors.Is(err, http.ErrServerClosed) {
		return nil
	}
	return err
}
