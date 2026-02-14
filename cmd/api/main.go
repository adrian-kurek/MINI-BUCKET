package main

import (
	"context"
	"errors"
	"fmt"
	"net/http"
	"os"
	"os/signal"

	config "github.com/slodkiadrianek/MINI-BUCKET/configs"
	"github.com/slodkiadrianek/MINI-BUCKET/internal/auth/controller"
	authRepository "github.com/slodkiadrianek/MINI-BUCKET/internal/auth/repository"
	"github.com/slodkiadrianek/MINI-BUCKET/internal/auth/service"
	"github.com/slodkiadrianek/MINI-BUCKET/internal/log"
	"github.com/slodkiadrianek/MINI-BUCKET/internal/server"
	userRepository "github.com/slodkiadrianek/MINI-BUCKET/internal/user/repository"
)

func main() {
	loggerService := log.NewLogger("./logs", "2006-01-02", "15:04:05")
	defer func() {
		if closeErr := loggerService.Close(); closeErr != nil {
			fmt.Printf("failed to properly close file with logs:%s", closeErr.Error())
		}
	}()
	err := config.SetupEnvVariables("./.env")
	if err != nil {
		panic(err)
	}

	port, ok := os.LookupEnv("PORT")
	if !ok {
		err := errors.New("PORT variable has not been initialized")
		loggerService.Error(err.Error(), map[string]string{
			"variable": "PORT",
		})
		panic(err)
	}

	dbLink, ok := os.LookupEnv("DbLink")
	if !ok {
		err := errors.New("DbLink variable has not been initialized")
		loggerService.Error(err.Error(), map[string]string{
			"variable": "DbLink",
		})
		panic(err)
	}

	db, err := config.NewDB(dbLink, "postgres")
	if err != nil {
		loggerService.Error("Failed to connect to database", err)
		panic(err)
	}

	userRepository := userRepository.NewUserRepository(loggerService, db.DBConnection)
	authRepository := authRepository.NewAuthRepository(loggerService, db.DBConnection)
	authService := service.NewAuthService(loggerService, userRepository, authRepository)
	authController := controller.NewAuthController(loggerService, authService)

	dependenciesConfig := server.NewDependencyConfig(port, *authController)
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
