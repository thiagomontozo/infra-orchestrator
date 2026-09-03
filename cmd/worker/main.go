package main

import (
	"github.com/thiagomontozo/infra-orchestrator/internal/app"
	"log/slog"
	"os"
)

func main() {
	if e := app.Run(true); e != nil {
		slog.Error("worker failed", "error", e)
		os.Exit(1)
	}
}
