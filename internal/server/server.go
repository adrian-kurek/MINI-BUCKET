// Package server hold whole logic associated with server and router
package server

import (
	"context"
	"net/http"
	"time"

	authHandler "github.com/slodkiadrianek/MINI-BUCKET/internal/auth/handler"
	authRoutes "github.com/slodkiadrianek/MINI-BUCKET/internal/auth/routes"
	objectHandler "github.com/slodkiadrianek/MINI-BUCKET/internal/objects/handler"
	objectRoutes "github.com/slodkiadrianek/MINI-BUCKET/internal/objects/routes"
	permissionHandler "github.com/slodkiadrianek/MINI-BUCKET/internal/permissions/handler"
	permissionRoutes "github.com/slodkiadrianek/MINI-BUCKET/internal/permissions/routes"
)

type DependencyConfig struct {
	port              string
	authController    authHandler.AuthHandler
	objectController  objectHandler.ObjectHandler
	permissionHandler permissionHandler.PermissionHandler
}

func NewDependencyConfig(port string, authController authHandler.AuthHandler, objectController objectHandler.ObjectHandler, permissionHandler permissionHandler.PermissionHandler) *DependencyConfig {
	return &DependencyConfig{
		port:              port,
		authController:    authController,
		objectController:  objectController,
		permissionHandler: permissionHandler,
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
		ReadTimeout:  50 * time.Second,
		WriteTimeout: 50 * time.Second,
		IdleTimeout:  30 * time.Second,
	}
	return s.server.ListenAndServe()
}

func (s *Server) SetupRoutes() {
	authHandler := authRoutes.NewAuthRoutes(&s.config.authController)
	authHandler.SetupAuthRoutes(s.router)
	objectHandler := objectRoutes.NewObjectRoutes(&s.config.objectController)
	objectHandler.SetupObjectRoutes(s.router)
	permissionRoutes := permissionRoutes.NewPermissionRoutes(&s.config.permissionHandler)
	permissionRoutes.SetupPermissionRoutes(s.router)
}

func (s *Server) Shutdown(ctx context.Context) error {
	return s.server.Shutdown(ctx)
}
