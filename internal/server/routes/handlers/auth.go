package handlers

import (
	"net/http"

	"github.com/slodkiadrianek/MINI-BUCKET/internal/server/routes"
)

type authController interface {
	Login(w http.ResponseWriter, r *http.Request)
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

	groupRouter.GET("/login", ah.authController.Login)
}
