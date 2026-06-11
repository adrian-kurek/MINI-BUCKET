// Package server hold whole logic associated with server and router
package server

import (
	"context"
	"net/http"
	"time"

	authController "github.com/slodkiadrianek/MINI-BUCKET/internal/auth/controller"
	objectController "github.com/slodkiadrianek/MINI-BUCKET/internal/objects/controller"
	"github.com/slodkiadrianek/MINI-BUCKET/internal/server/routes"
)

type DependencyConfig struct {
	port             string
	authController   authController.AuthController
	objectController objectController.ObjectController
}

func NewDependencyConfig(port string, authController authController.AuthController, objectController objectController.ObjectController) *DependencyConfig {
	return &DependencyConfig{
		port:             port,
		authController:   authController,
		objectController: objectController,
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
	authHandler := routes.NewAuthHandler(&s.config.authController)
	authHandler.SetupAuthHandlers(s.router)
	objectHandler := routes.NewObjectHandler(&s.config.objectController)
	objectHandler.SetupObjectHandlers(s.router)
}

func (s *Server) Shutdown(ctx context.Context) error {
	return s.server.Shutdown(ctx)
}
