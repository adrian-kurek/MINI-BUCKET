// Package routes
package routes

import (
	"fmt"
	"net/http"

	"github.com/slodkiadrianek/MINI-BUCKET/internal/common/request"
)

type authController interface {
	Register(w http.ResponseWriter, r *http.Request) error
	Login(w http.ResponseWriter, r *http.Request) error
	RefreshToken(w http.ResponseWriter, r *http.Request) error
	LogoutUser(w http.ResponseWriter, r *http.Request) error
	Verify(w http.ResponseWriter, r *http.Request) error
	LogoutUserFromAllDevices(w http.ResponseWriter, r *http.Request) error
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
	router.Handle(fmt.Sprintf("POST %s/login", prefix), request.Make(ah.authController.Login))
	router.Handle(fmt.Sprintf("POST %s/refreshToken", prefix), request.Make(ah.authController.RefreshToken))
	router.Handle(fmt.Sprintf("DELETE %s/logout", prefix), request.Make(ah.authController.LogoutUser))
	router.Handle(fmt.Sprintf("GET %s/verify", prefix), request.Make(ah.authController.Verify))
	router.Handle(fmt.Sprintf("DELETE %s/logoutAll", prefix), request.Make(ah.authController.LogoutUserFromAllDevices))
}
