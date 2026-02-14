// Package controller hold whole logic associated with controller
package controller

import (
	"context"
	"errors"
	"net/http"
	"time"

	authDto "github.com/slodkiadrianek/MINI-BUCKET/internal/auth/DTO"
	commonInterfaces "github.com/slodkiadrianek/MINI-BUCKET/internal/common/interfaces"

	commonErrors "github.com/slodkiadrianek/MINI-BUCKET/internal/common/errors"
	"github.com/slodkiadrianek/MINI-BUCKET/internal/common/request"
	"github.com/slodkiadrianek/MINI-BUCKET/internal/common/response"
)

type authService interface {
	Register(ctx context.Context, user authDto.CreateUser) error
}

type AuthController struct {
	loggerService commonInterfaces.Logger
	authService   authService
}

func NewAuthController(loggerService commonInterfaces.Logger, authService authService) *AuthController {
	return &AuthController{
		loggerService: loggerService,
		authService:   authService,
	}
}

func (ac *AuthController) Register(w http.ResponseWriter, r *http.Request) error {
	ctx, cancel := context.WithTimeout(r.Context(), 2*time.Second)
	defer cancel()
	req, err := request.ReadBody[authDto.CreateUser](r)
	if err != nil {
		return err
	}
	err = ac.authService.Register(ctx, *req)
	if err != nil {
		if errors.Is(err, context.DeadlineExceeded) {
			ac.loggerService.Info("request timed out", nil)
			return commonErrors.NewAPIError(http.StatusRequestTimeout, "")
		}
		return err
	}

	response.Send(w, http.StatusOK, map[string]string{})
	return nil
}
