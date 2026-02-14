// Package routes
package routes

import (
	"fmt"
	"net/http"

	"github.com/slodkiadrianek/MINI-BUCKET/internal/common/request"
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

func (ah *AuthHandler) SetupAuthHandlers(router *http.ServeMux) {
	prefix := "/auth"
	router.Handle(fmt.Sprintf("POST %s/register", prefix), request.Make(ah.authController.Register))
}
