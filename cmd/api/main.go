package main

import (
	"context"
	"errors"
	"fmt"
	"net/http"
	"os"
	"os/signal"

	"github.com/slodkiadrianek/MINI-BUCKET/common/log"
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

	_, ok := os.LookupEnv("HOST_LINK")
	if !ok {
		err = errors.New("HOST_LINK variable has not been initialized")
		loggerService.Error(err.Error(), map[string]string{
			"variable": "HOST_LINK",
		})
		panic(err)
	}

	port, ok := os.LookupEnv("PORT")
	if !ok {
		err = errors.New("PORT variable has not been initialized")
		loggerService.Error(err.Error(), map[string]string{
			"variable": "PORT",
		})
		panic(err)
	}

	dbLink, ok := os.LookupEnv("DB_LINK")
	if !ok {
		err = errors.New("DB_LINK variable has not been initialized")
		loggerService.Error(err.Error(), map[string]string{
			"variable": "DB_LINK",
		})
		panic(err)
	}

	db, err := config.NewDB(dbLink, "postgres")
	if err != nil {
		loggerService.Error("Failed to connect to database", err)
		panic(err)
	}

	cacheConnectionLink, ok := os.LookupEnv("CACHE_LINK")
	if !ok {
		err = errors.New("CACHE_LINK variable has not been initialized")
		loggerService.Error(err.Error(), map[string]string{
			"variable": "CACHE_LINK",
		})
		panic(err)
	}

	cacheService, err := config.NewCacheService(cacheConnectionLink)
	if err != nil {
		loggerService.Error("failed to connect to cache service", err.Error())
		panic(err)
	}

	accessTokenSecret, ok := os.LookupEnv("ACCESS_TOKEN_SECRET")
	if !ok {
		err = errors.New("ACCESS_TOKEN_SECRET variable has not been initialized")
		loggerService.Error(err.Error(), map[string]string{
			"variable": "ACCESS_TOKEN_SECRET",
		})
		panic(err)
	}

	refreshTokenSecret, ok := os.LookupEnv("REFRESH_TOKEN_SECRET")
	if !ok {
		err = errors.New("REFRESH_TOKEN_SECRET variable has not been initialized")
		loggerService.Error(err.Error(), map[string]string{
			"variable": "REFRESH_TOKEN_SECRET",
		})
		panic(err)
	}

	hostEmail, ok := os.LookupEnv("HOST_EMAIL")
	if !ok {
		err = errors.New("HOST_EMAIL variable has not been initialized")
		loggerService.Error(err.Error(), map[string]string{
			"variable": "HOST_EMAIL",
		})
		panic(err)
	}

	passwordEmail, ok := os.LookupEnv("PASSWORD_EMAIL")
	if !ok {
		err = errors.New("PASSWORD_EMAIL variable has not been initialized")
		loggerService.Error(err.Error(), map[string]string{
			"variable": "PASSWORD_EMAIL",
		})
		panic(err)
	}

	authorization := middleware.NewAuthenticationMiddleware(accessTokenSecret, refreshTokenSecret, loggerService, cacheService)
	mailService := mailService.NewEmailService(hostEmail, passwordEmail, loggerService)
	userRepository := userRepository.NewUserRepository(loggerService, db.DBConnection)
	authRepository := authRepository.NewAuthRepository(loggerService, db.DBConnection)
	authService := authService.NewAuthService(loggerService, userRepository, authRepository, authorization, mailService)
	authHandler := authHandler.NewAuthHandler(loggerService, authService, authorization)

	permissionRepository := permissionRepository.NewPermissionRepository(loggerService, db.DBConnection)
	permissionService := permissionService.NewPermissionRepository(permissionRepository, loggerService)
	permissionHandler := permissionHandler.NewPermissionHandler(permissionService, authorization, loggerService)
	bucketRepository := bucketRepository.NewBucketRepository(loggerService, db.DBConnection)
	bucketService := bucketService.NewBucketService(bucketRepository, permissionRepository, loggerService)
	bucketHandler := bucketHandler.NewBucketHandler(bucketService, authorization, loggerService)
	objectRepository := objectRepository.NewObjectRepository(db.DBConnection, loggerService)
	versionRepository := versionRepository.NewVersionRepository(db.DBConnection, loggerService)
	objectService := objectService.NewObjectService(loggerService, objectRepository, permissionRepository, bucketRepository, db.DBConnection, versionRepository)

	objectHandler := objectHandler.NewObjectHandler(loggerService, authorization, objectService)

	dependenciesConfig := server.NewDependencyConfig(port, *authHandler, *objectHandler, *permissionHandler, *bucketHandler)
	apiCtx, apiCtxCancel := context.WithCancel(context.Background())
	httpServer := server.NewServer(dependenciesConfig)
	go func() {
		loggerService.Info(fmt.Sprintf("server started at port:%s", port), nil)
		if err = httpServer.Start(); err != nil && !errors.Is(err, http.ErrServerClosed) {
			loggerService.Error("Failed to start server", err)
		}
	}()

	quit := make(chan os.Signal, 1)
	signal.Notify(quit, os.Interrupt)
	<-quit
	defer apiCtxCancel()

	if err = httpServer.Shutdown(apiCtx); err != nil {
		loggerService.Error("Server forced to shutdown:", err)
		err = loggerService.Close()
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

	loggerService.Info("server exited", nil)
}
