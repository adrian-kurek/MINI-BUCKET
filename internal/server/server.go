package server

import (
	"context"
	"fmt"
	"net/http"
	"time"

	"github.com/slodkiadrianek/MINI-BUCKET/internal/server/routes"
)

type DependencyConfig struct {
	port string
}

func NewDependencyConfig(port string) *DependencyConfig {
	return &DependencyConfig{
		port: port,
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
	fmt.Print("test")
}

func (s *Server) Shutdown(ctx context.Context) error {
	return s.server.Shutdown(ctx)
}
