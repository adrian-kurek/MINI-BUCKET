package main

import (
	"context"
	"errors"
	"fmt"
	"log"
	"net/http"
	"os"
	"os/signal"

	"github.com/slodkiadrianek/MINI-BUCKET/common/logger"
	"github.com/slodkiadrianek/MINI-BUCKET/common/middleware"
	config "github.com/slodkiadrianek/MINI-BUCKET/configs"
	authHandler "github.com/slodkiadrianek/MINI-BUCKET/internal/auth/handler"
	authRepository "github.com/slodkiadrianek/MINI-BUCKET/internal/auth/repository"
	authService "github.com/slodkiadrianek/MINI-BUCKET/internal/auth/service"
	bucketHandler "github.com/slodkiadrianek/MINI-BUCKET/internal/bucket/handler"
	bucketRepository "github.com/slodkiadrianek/MINI-BUCKET/internal/bucket/repository"
	bucketService "github.com/slodkiadrianek/MINI-BUCKET/internal/bucket/service"
	mailService "github.com/slodkiadrianek/MINI-BUCKET/internal/mail"
	objectHandler "github.com/slodkiadrianek/MINI-BUCKET/internal/objects/handler"
	objectRepository "github.com/slodkiadrianek/MINI-BUCKET/internal/objects/repository"
	objectService "github.com/slodkiadrianek/MINI-BUCKET/internal/objects/service"
	permissionHandler "github.com/slodkiadrianek/MINI-BUCKET/internal/permissions/handler"
	permissionRepository "github.com/slodkiadrianek/MINI-BUCKET/internal/permissions/repository"
	permissionService "github.com/slodkiadrianek/MINI-BUCKET/internal/permissions/service"
	"github.com/slodkiadrianek/MINI-BUCKET/internal/server"
	userRepository "github.com/slodkiadrianek/MINI-BUCKET/internal/user/repository"
	versionRepository "github.com/slodkiadrianek/MINI-BUCKET/internal/versions/repository"
)

func main() {
	loggerSvc := logger.New("./logs", "2006-01-02", "15:04:05")
	defer func() {
		if closeErr := loggerSvc.Close(); closeErr != nil {
			log.Printf("failed to properly close file with logs:%s", closeErr.Error())
		}
	}()
	err := config.SetupEnvVariables("./.env")
	if err != nil {
		panic(err)
	}

	_, ok := os.LookupEnv("HOST_LINK")
	if !ok {
		err = errors.New("HOST_LINK variable has not been initialized")
		loggerSvc.Error(err.Error(), map[string]string{
			"variable": "HOST_LINK",
		})
		panic(err)
	}

	port, ok := os.LookupEnv("PORT")
	if !ok {
		err = errors.New("PORT variable has not been initialized")
		loggerSvc.Error(err.Error(), map[string]string{
			"variable": "PORT",
		})
		panic(err)
	}

	dbLink, ok := os.LookupEnv("DB_LINK")
	if !ok {
		err = errors.New("DB_LINK variable has not been initialized")
		loggerSvc.Error(err.Error(), map[string]string{
			"variable": "DB_LINK",
		})
		panic(err)
	}

	db, err := config.NewDB(dbLink, "postgres")
	if err != nil {
		loggerSvc.Error("Failed to connect to database", err)
		panic(err)
	}

	cacheConnectionLink, ok := os.LookupEnv("CACHE_LINK")
	if !ok {
		err = errors.New("CACHE_LINK variable has not been initialized")
		loggerSvc.Error(err.Error(), map[string]string{
			"variable": "CACHE_LINK",
		})
		panic(err)
	}

	cacheService, err := config.NewCacheService(cacheConnectionLink)
	if err != nil {
		loggerSvc.Error("failed to connect to cache service", err.Error())
		panic(err)
	}

	accessTokenSecret, ok := os.LookupEnv("ACCESS_TOKEN_SECRET")
	if !ok {
		err = errors.New("ACCESS_TOKEN_SECRET variable has not been initialized")
		loggerSvc.Error(err.Error(), map[string]string{
			"variable": "ACCESS_TOKEN_SECRET",
		})
		panic(err)
	}

	refreshTokenSecret, ok := os.LookupEnv("REFRESH_TOKEN_SECRET")
	if !ok {
		err = errors.New("REFRESH_TOKEN_SECRET variable has not been initialized")
		loggerSvc.Error(err.Error(), map[string]string{
			"variable": "REFRESH_TOKEN_SECRET",
		})
		panic(err)
	}

	hostEmail, ok := os.LookupEnv("HOST_EMAIL")
	if !ok {
		err = errors.New("HOST_EMAIL variable has not been initialized")
		loggerSvc.Error(err.Error(), map[string]string{
			"variable": "HOST_EMAIL",
		})
		panic(err)
	}

	passwordEmail, ok := os.LookupEnv("PASSWORD_EMAIL")
	if !ok {
		err = errors.New("PASSWORD_EMAIL variable has not been initialized")
		loggerSvc.Error(err.Error(), map[string]string{
			"variable": "PASSWORD_EMAIL",
		})
		panic(err)
	}

	authentication := middleware.New(
		accessTokenSecret,
		refreshTokenSecret,
		loggerSvc,
		cacheService,
	)
	mailSvc := mailService.New(hostEmail, passwordEmail, loggerSvc)
	userRepo := userRepository.New(loggerSvc, db.DBConnection)
	authRepo := authRepository.New(loggerSvc, db.DBConnection)
	authSvc := authService.NewAuthService(loggerSvc, userRepo, authRepo, authentication, mailSvc)
	authH := authHandler.New(loggerSvc, authSvc, authentication)

	permissionRepo := permissionRepository.NewPermissionRepository(loggerSvc, db.DBConnection)
	permissionSvc := permissionService.NewPermissionRepository(permissionRepo, loggerSvc)
	permissionH := permissionHandler.NewPermissionHandler(permissionSvc, authentication, loggerSvc)
	bucketRepo := bucketRepository.New(loggerSvc, db.DBConnection)
	bucketSvc := bucketService.New(bucketRepo, permissionRepo, loggerSvc)
	bucketH := bucketHandler.New(bucketSvc, authentication, loggerSvc)
	objectRepo := objectRepository.New(db.DBConnection, loggerSvc)
	versionRepo := versionRepository.New(db.DBConnection, loggerSvc)
	objectSvc := objectService.New(
		loggerSvc,
		objectRepo,
		permissionRepo,
		bucketRepo,
		db.DBConnection,
		versionRepo,
	)

	objectH := objectHandler.New(loggerSvc, authentication, objectSvc)

	dependenciesConfig := server.NewDependencyConfig(
		port,
		*authH,
		*objectH,
		*permissionH,
		*bucketH,
	)
	apiCtx, apiCtxCancel := context.WithCancel(context.Background())
	httpServer := server.NewServer(dependenciesConfig)
	go func() {
		loggerSvc.Info(fmt.Sprintf("server started at port:%s", port), nil)
		if err = httpServer.Start(); err != nil && !errors.Is(err, http.ErrServerClosed) {
			loggerSvc.Error("Failed to start server", err)
		}
	}()

	quit := make(chan os.Signal, 1)
	signal.Notify(quit, os.Interrupt)
	<-quit
	defer apiCtxCancel()

	if err = httpServer.Shutdown(apiCtx); err != nil {
		loggerSvc.Error("Server forced to shutdown:", err)
		err = loggerSvc.Close()
		if err != nil {
			panic(err)
		}
		err = db.Close()
		if err != nil {
			panic(err)
		}
		err = cacheService.Close()
		if err != nil {
			panic(err)
		}
	}

	loggerSvc.Info("server exited", nil)
}
