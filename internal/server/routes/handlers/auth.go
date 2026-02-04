package handlers

import (
	"net/http"

	"github.com/slodkiadrianek/MINI-BUCKET/internal/middleware"
	"github.com/slodkiadrianek/MINI-BUCKET/internal/server/routes"
)

type authController interface {
	Register(w http.ResponseWriter, r *http.Request) error
}

type AuthHandler struct {
	authController authController
}

func NewAuthHandler(authController authController) *AuthHandler {
	return &AuthHandler{
		authController: authController,
	}
}

func (ah *AuthHandler) SetupAuthHandlers(router *routes.Router) {
	groupRouter := router.Group("/api/v1/auth")

	groupRouter.POST("/register", middleware.Make(ah.authController.Register))
}
