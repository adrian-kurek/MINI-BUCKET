// Package controller hold whole logic associated with controller
package controller

import (
	"context"
	"errors"
	"net/http"
	"os"
	"time"

	authDto "github.com/slodkiadrianek/MINI-BUCKET/internal/auth/DTO"
	commonInterfaces "github.com/slodkiadrianek/MINI-BUCKET/internal/common/interfaces"
	"github.com/slodkiadrianek/MINI-BUCKET/internal/middleware"

	commonErrors "github.com/slodkiadrianek/MINI-BUCKET/internal/common/errors"
	"github.com/slodkiadrianek/MINI-BUCKET/internal/common/request"
	"github.com/slodkiadrianek/MINI-BUCKET/internal/common/response"
)

type authService interface {
	Register(ctx context.Context, user authDto.CreateUser) error
	Login(ctx context.Context, loginData authDto.LoginUser, ipAddress, deviceInfo string) (string, string, error)
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

	reqData, err := request.ReadBody[authDto.CreateUser](r)
	if err != nil {
		return err
	}

	err = middleware.ValidateRequestData(reqData)
	if err != nil {
		return err
	}

	err = ac.authService.Register(ctx, *reqData)
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

func (ac *AuthController) Login(w http.ResponseWriter, r *http.Request) error {
	ctx, cancel := context.WithTimeout(r.Context(), 2*time.Second)
	defer cancel()

	reqData, err := request.ReadBody[authDto.LoginUser](r)
	if err != nil {
		return err
	}

	ipAddress := r.RemoteAddr
	deviceInfo := r.UserAgent()

	accessToken, refreshToken, err := ac.authService.Login(ctx, *reqData, ipAddress, deviceInfo)
	if err != nil {
		return err
	}

	expiration := time.Now().Add(7 * 24 * time.Hour)
	cookie := http.Cookie{
		Name:     "refreshToken",
		Value:    refreshToken,
		Expires:  expiration,
		Secure:   os.Getenv("NODE_ENV") == "production",
		SameSite: http.SameSiteStrictMode,
		HttpOnly: true,
	}

	http.SetCookie(w, &cookie)
	response.Send(w, http.StatusOK, map[string]string{"token": accessToken})

	return nil
}
