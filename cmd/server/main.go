package main

import (
	"github.com/thiagomontozo/infra-orchestrator/internal/app"
	"log/slog"
	"os"
)

func main() {
	if e := app.Run(false); e != nil {
		slog.Error("startup failed", "error", e)
		os.Exit(1)
	}
}
