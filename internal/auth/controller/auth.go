// Package controller hold whole logic associated with controller
package controller

import (
	"context"
	"errors"
	"net/http"
	"time"

	"github.com/slodkiadrianek/MINI-BUCKET/internal/common/interfaces"
	"github.com/slodkiadrianek/MINI-BUCKET/internal/user/model"
	"github.com/slodkiadrianek/MINI-BUCKET/internal/utils/response"
)

type authService interface {
	Register(ctx context.Context, user model.User) error
}

type AuthController struct {
	loggerService interfaces.Logger
	authService   authService
}

func NewAuthController(loggerService interfaces.Logger, authService authService) *AuthController {
	return &AuthController{
		loggerService: loggerService,
		authService:   authService,
	}
}

func (ac *AuthController) Register(w http.ResponseWriter, r *http.Request) {
	ctx, cancel := context.WithTimeout(r.Context(), 800*time.Millisecond)
	defer cancel()
	err := ac.authService.Register(ctx, model.User{})
	if err != nil {
		if errors.Is(err, context.DeadlineExceeded) {
			response.Send(w, http.StatusGatewayTimeout, "register timed out")
		}
	}
	response.Send(w, http.StatusOK, map[string]string{})
}
