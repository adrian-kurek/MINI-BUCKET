// Package routes
package routes

import (
	"fmt"
	"net/http"

	"github.com/slodkiadrianek/MINI-BUCKET/common/request"
)

type authController interface {
	Register(w http.ResponseWriter, r *http.Request) error
	Login(w http.ResponseWriter, r *http.Request) error
	RefreshToken(w http.ResponseWriter, r *http.Request) error
	LogoutUser(w http.ResponseWriter, r *http.Request) error
	Verify(w http.ResponseWriter, r *http.Request) error
	LogoutUserFromAllDevices(w http.ResponseWriter, r *http.Request) error
	ActivateAccount(w http.ResponseWriter, r *http.Request) error
}

type AuthRoutes struct {
	authController authController
}

func New(authController authController) *AuthRoutes {
	return &AuthRoutes{
		authController: authController,
	}
}

func (ah *AuthRoutes) SetupAuthRoutes(router *http.ServeMux) {
	prefix := "/auth"
	router.Handle(fmt.Sprintf("POST %s/register", prefix), request.Make(ah.authController.Register))
	router.Handle(fmt.Sprintf("POST %s/login", prefix), request.Make(ah.authController.Login))
	router.Handle(fmt.Sprintf("POST %s/refreshToken", prefix), request.Make(ah.authController.RefreshToken))
	router.Handle(fmt.Sprintf("DELETE %s/logout", prefix), request.Make(ah.authController.LogoutUser))
	router.Handle(fmt.Sprintf("DELETE %s/logoutAll", prefix), request.Make(ah.authController.LogoutUserFromAllDevices))
	router.Handle(fmt.Sprintf("GET %s/verify", prefix), request.Make(ah.authController.Verify))
	router.Handle(fmt.Sprintf("GET %s/activateAccount", prefix), request.Make(ah.authController.ActivateAccount))
}
