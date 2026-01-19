// Package controller hold whole logic associated with controller
package controller

import (
	"net/http"

	"github.com/slodkiadrianek/MINI-BUCKET/internal/interfaces"
	"github.com/slodkiadrianek/MINI-BUCKET/internal/utils/response"
)

type AuthController struct {
	loggerService interfaces.Logger
}

func NewAuthController(loggerService interfaces.Logger) *AuthController {
	return &AuthController{
		loggerService: loggerService,
	}
}

func (ac *AuthController) Register(w http.ResponseWriter, r *http.Request) {
	ac.loggerService.Info("Started register process", "")
	response.Send(w, http.StatusOK, map[string]string{})
}
