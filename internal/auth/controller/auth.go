// Package controller hold whole logic associated with controller
package controller

import (
	"context"
	"net/http"

	authDto "github.com/slodkiadrianek/MINI-BUCKET/internal/auth/DTO"
	commonInterfaces "github.com/slodkiadrianek/MINI-BUCKET/internal/common/interfaces"
	"github.com/slodkiadrianek/MINI-BUCKET/internal/middleware"
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
	// ctx, cancel := context.WithTimeout(r.Context(), 2*time.Second)
	// defer cancel()
	return middleware.NewAPIError(400, "TEST ISSUE")
	// dataFromBody, err := request.ReadBody[authDto.CreateUser](r)
	// if err != nil {
	// 	response.Send(w, 400, err.Error())
	// 	return
	// }
	// err = ac.authService.Register(ctx, *dataFromBody)
	// if err != nil {
	// 	if errors.Is(err, context.DeadlineExceeded) {
	// 		response.Send(w, http.StatusGatewayTimeout, "register timed out")
	// 		return
	// 	}
	// 	response.Send(w, http.StatusInternalServerError, err.Error())
	// 	return
	// }
	//
	// response.Send(w, http.StatusOK, map[string]string{})
	// return
}
