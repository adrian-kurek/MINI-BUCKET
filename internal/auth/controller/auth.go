// Package controller hold whole logic associated with controller
package controller

import (
	"context"
	"errors"
	"net/http"
	"time"

	dto "github.com/slodkiadrianek/MINI-BUCKET/internal/auth/DTO"
	"github.com/slodkiadrianek/MINI-BUCKET/internal/common/interfaces"
	"github.com/slodkiadrianek/MINI-BUCKET/internal/utils/request"
	"github.com/slodkiadrianek/MINI-BUCKET/internal/utils/response"
)

type authService interface {
	Register(ctx context.Context, user dto.CreateUser) error
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
	dataFromBody, err := request.ReadBody[dto.CreateUser](r)
	if err != nil {
		response.Send(w, 400, err.Error())
	}
	err = ac.authService.Register(ctx, *dataFromBody)
	if err != nil {
		if errors.Is(err, context.DeadlineExceeded) {
			response.Send(w, http.StatusGatewayTimeout, "register timed out")
		}
	}
	response.Send(w, http.StatusOK, map[string]string{})
}
