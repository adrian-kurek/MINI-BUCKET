package main

import (
	"context"
	"errors"
	"fmt"
	"net/http"
	"os"
	"os/signal"

	"github.com/slodkiadrianek/MINI-BUCKET/internal/log"
	"github.com/slodkiadrianek/MINI-BUCKET/internal/server"
)

func main() {
	loggerService := log.NewLogger("../../logs", "2025.08.12", "21:02:03")
	defer func() {
		if closeErr := loggerService.Close(); closeErr != nil {
			fmt.Printf("failed to properly close file with logs:%s", closeErr.Error())
		}
	}()
	port := "3009"
	// if !ok {
	// 	err := errors.New("PORT variable has not been initialized")
	// 	loggerService.Error(err.Error(), map[string]string{
	// 		"variable": "PORT",
	// 	})
	// 	panic(err)
	// }
	dependenciesConfig := server.NewDependencyConfig(port)
	apiCtx, apiCtxCancel := context.WithCancel(context.Background())
	httpServer := server.NewServer(dependenciesConfig)
	go func() {
		loggerService.Info(fmt.Sprintf("server started at port:%s", port), nil)
		if err := httpServer.Start(); err != nil && !errors.Is(err, http.ErrServerClosed) {
			loggerService.Error("Failed to start server", err)
		}
	}()

	quit := make(chan os.Signal, 1)
	signal.Notify(quit, os.Interrupt)
	<-quit
	defer apiCtxCancel()

	if err := httpServer.Shutdown(apiCtx); err != nil {
		loggerService.Error("Server forced to shutdown:", err)
	}

	loggerService.Info("server exited", nil)
}
