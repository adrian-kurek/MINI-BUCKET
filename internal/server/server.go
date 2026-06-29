// Package server hold whole logic associated with server and router
package server

import (
	"context"
	"net/http"
	"time"

	authHandler "github.com/slodkiadrianek/MINI-BUCKET/internal/auth/handler"
	authRoutes "github.com/slodkiadrianek/MINI-BUCKET/internal/auth/routes"
	bucketHandler "github.com/slodkiadrianek/MINI-BUCKET/internal/bucket/handler"
	bucketRoutes "github.com/slodkiadrianek/MINI-BUCKET/internal/bucket/routes"
	objectHandler "github.com/slodkiadrianek/MINI-BUCKET/internal/objects/handler"
	objectRoutes "github.com/slodkiadrianek/MINI-BUCKET/internal/objects/routes"
	permissionHandler "github.com/slodkiadrianek/MINI-BUCKET/internal/permissions/handler"
	permissionRoutes "github.com/slodkiadrianek/MINI-BUCKET/internal/permissions/routes"
)

const (
	defaultReadTimeout  = 50 * time.Second
	defaultWriteTimeout = 50 * time.Second
	defaultIdleTimeout  = 30 * time.Second
)

type DependencyConfig struct {
	port              string
	authHandler       authHandler.AuthHandler
	objectHandler     objectHandler.ObjectHandler
	permissionHandler permissionHandler.PermissionHandler
	bucketHandler     bucketHandler.BucketHandler
}

func NewDependencyConfig(
	port string,
	authHandler authHandler.AuthHandler,
	objectHandler objectHandler.ObjectHandler,
	permissionHandler permissionHandler.PermissionHandler,
	bucketHandler bucketHandler.BucketHandler,
) *DependencyConfig {
	return &DependencyConfig{
		port:              port,
		authHandler:       authHandler,
		objectHandler:     objectHandler,
		permissionHandler: permissionHandler,
		bucketHandler:     bucketHandler,
	}
}

type Server struct {
	config *DependencyConfig
	server *http.Server
	router *http.ServeMux
}

func NewServer(config *DependencyConfig) *Server {
	return &Server{
		config: config,
		router: http.NewServeMux(),
	}
}

func (s *Server) Start() error {
	s.SetupRoutes()
	s.server = &http.Server{
		Addr:         ":" + s.config.port,
		Handler:      s.router,
		ReadTimeout:  defaultReadTimeout,
		WriteTimeout: defaultWriteTimeout,
		IdleTimeout:  defaultIdleTimeout,
	}
	return s.server.ListenAndServe()
}

func (s *Server) SetupRoutes() {
	authRoutes := authRoutes.NewAuthRoutes(&s.config.authHandler)
	authRoutes.SetupAuthRoutes(s.router)
	objectRoutes := objectRoutes.NewObjectRoutes(&s.config.objectHandler)
	objectRoutes.SetupObjectRoutes(s.router)
	permissionRoutes := permissionRoutes.NewPermissionRoutes(&s.config.permissionHandler)
	permissionRoutes.SetupPermissionRoutes(s.router)
	bucketRoutes := bucketRoutes.NewBucketRoutes(&s.config.bucketHandler)
	bucketRoutes.SetupBucketRoutes(s.router)
}

func (s *Server) Shutdown(ctx context.Context) error {
	return s.server.Shutdown(ctx)
}
