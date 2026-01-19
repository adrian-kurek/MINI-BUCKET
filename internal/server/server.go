package server

import (
	"context"
	"net/http"
	"time"

	"github.com/slodkiadrianek/MINI-BUCKET/internal/auth/controller"
	"github.com/slodkiadrianek/MINI-BUCKET/internal/server/routes"
	"github.com/slodkiadrianek/MINI-BUCKET/internal/server/routes/handlers"
)

type DependencyConfig struct {
	port           string
	authController controller.AuthController
}

func NewDependencyConfig(port string, authController controller.AuthController) *DependencyConfig {
	return &DependencyConfig{
		port:           port,
		authController: authController,
	}
}

type Server struct {
	config *DependencyConfig
	server *http.Server
	router *routes.Router
}

func NewServer(config *DependencyConfig) *Server {
	return &Server{
		config: config,
		router: routes.NewRouter(),
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
	authHandler := handlers.NewAuthHandler(&s.config.authController)
	authHandler.SetupAuthHandlers(s.router)
}

func (s *Server) Shutdown(ctx context.Context) error {
	return s.server.Shutdown(ctx)
}
