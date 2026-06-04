// Package controller hold whole logic associated with controller
package controller

import (
	"context"
	"encoding/hex"
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

const authTimeout = 2 * time.Second

type authService interface {
	Register(ctx context.Context, user authDto.CreateUser) error
	Login(ctx context.Context, loginData authDto.LoginUser, ipAddress, deviceInfo string) (string, []byte, error)
	RefreshToken(ctx context.Context, token []byte) (string, error)
	LogoutUser(ctx context.Context, refreshToken []byte) error
	LogoutUserFromAllDevices(ctx context.Context, userID int) error
	ActivateAccount(ctx context.Context, userID int) error
}

type AuthController struct {
	loggerService commonInterfaces.Logger
	authService   authService
	authorization commonInterfaces.AuthorizationMiddleware
}

func NewAuthController(loggerService commonInterfaces.Logger, authService authService, authorization commonInterfaces.AuthorizationMiddleware) *AuthController {
	return &AuthController{
		loggerService: loggerService,
		authService:   authService,
		authorization: authorization,
	}
}

func (ac *AuthController) Register(w http.ResponseWriter, r *http.Request) error {
	ctx, cancel := context.WithTimeout(r.Context(), authTimeout)
	defer cancel()

	reqData, err := request.ReadBody[authDto.CreateUser](r)
	if err != nil {
		return commonErrors.NewAPIError(http.StatusUnprocessableEntity, "provided invalid json format")
	}

	err = middleware.ValidateRequestData(reqData)
	if err != nil {
		return err
	}

	err = ac.authService.Register(ctx, *reqData)
	if err != nil {
		if errors.Is(err, context.DeadlineExceeded) {
			ac.loggerService.Info("request timed out", r.URL.Path)
			return commonErrors.NewAPIError(http.StatusRequestTimeout, "")
		}
		return err
	}

	response.Send(w, http.StatusOK, map[string]string{})
	return nil
}

func (ac *AuthController) Login(w http.ResponseWriter, r *http.Request) error {
	ctx, cancel := context.WithTimeout(r.Context(), authTimeout)
	defer cancel()

	reqData, err := request.ReadBody[authDto.LoginUser](r)
	if err != nil {
		return commonErrors.NewAPIError(http.StatusUnprocessableEntity, "provided invalid json format")
	}

	err = middleware.ValidateRequestData(reqData)
	if err != nil {
		return err
	}

	ipAddress := r.RemoteAddr
	deviceInfo := r.UserAgent()

	accessToken, refreshToken, err := ac.authService.Login(ctx, *reqData, ipAddress, deviceInfo)
	if err != nil {
		if errors.Is(err, context.DeadlineExceeded) {
			ac.loggerService.Info("request timed out", r.URL.Path)
			return commonErrors.NewAPIError(http.StatusRequestTimeout, "")
		}
		return err
	}

	expiration := time.Now().Add(7 * 24 * time.Hour)

	cookie := http.Cookie{
		Name:     "refreshToken",
		Value:    hex.EncodeToString(refreshToken),
		Expires:  expiration,
		Secure:   os.Getenv("GO_ENV") == "production",
		SameSite: http.SameSiteStrictMode,
		HttpOnly: true,
	}

	http.SetCookie(w, &cookie)
	response.Send(w, http.StatusOK, map[string]string{"token": accessToken})

	return nil
}

func (ac *AuthController) RefreshToken(w http.ResponseWriter, r *http.Request) error {
	ctx, cancel := context.WithTimeout(r.Context(), authTimeout)
	defer cancel()

	refreshToken, err := r.Cookie("refreshToken")
	if err != nil {
		ac.loggerService.Error("failed to read cookie from request", err.Error())
		return err
	}

	tokenBytes, err := hex.DecodeString(refreshToken.Value)
	if err != nil {
		ac.loggerService.Error("failed to decode string into bytes", err.Error())
		return err
	}

	newAccessToken, err := ac.authService.RefreshToken(ctx, tokenBytes)
	if err != nil {
		if errors.Is(err, context.DeadlineExceeded) {
			ac.loggerService.Info("request timed out", r.URL.Path)
			return commonErrors.NewAPIError(http.StatusRequestTimeout, "")
		}
		return err
	}

	response.Send(w, http.StatusOK, map[string]string{"token": newAccessToken})

	return nil
}

func (ac *AuthController) Verify(w http.ResponseWriter, r *http.Request) error {
	ctx, cancel := context.WithTimeout(r.Context(), authTimeout)
	defer cancel()

	r = r.WithContext(ctx)

	r, err := ac.authorization.VerifyToken(r)
	if err != nil {
		if errors.Is(err, context.DeadlineExceeded) {
			ac.loggerService.Info("request timed out", r.URL.Path)
			return commonErrors.NewAPIError(http.StatusRequestTimeout, "")
		}
		return err
	}

	return nil
}

func (ac *AuthController) ActivateAccount(w http.ResponseWriter, r *http.Request) error {
	ctx, cancel := context.WithTimeout(r.Context(), authTimeout)
	defer cancel()

	r = r.WithContext(ctx)

	authToken := request.ReadQueryParam(r, "token")
	r.Header.Set("Authorization", "Bearer "+authToken)

	r, err := ac.authorization.VerifyToken(r)
	if err != nil {
		if errors.Is(err, context.DeadlineExceeded) {
			ac.loggerService.Info("request timed out", r.URL.Path)
			return commonErrors.NewAPIError(http.StatusRequestTimeout, "")
		}
		return err
	}

	userID, err := request.ReadUserIDFromToken(r)
	if err != nil {
		return err
	}

	err = ac.authService.ActivateAccount(ctx, userID)
	if err != nil {
		if errors.Is(err, context.DeadlineExceeded) {
			ac.loggerService.Info("request timed out", r.URL.Path)
			return commonErrors.NewAPIError(http.StatusRequestTimeout, "")
		}
		return err
	}

	return nil
}

func (ac *AuthController) LogoutUser(w http.ResponseWriter, r *http.Request) error {
	ctx, cancel := context.WithTimeout(r.Context(), authTimeout)
	defer cancel()

	err := ac.authorization.BlacklistUser(r)
	if err != nil {
		if errors.Is(err, context.DeadlineExceeded) {
			ac.loggerService.Info("request timed out", r.URL.Path)
			return commonErrors.NewAPIError(http.StatusRequestTimeout, "")
		}
		return err
	}

	refreshToken, err := r.Cookie("refreshToken")
	if err != nil {
		ac.loggerService.Error("failed to read cookie from request", r.URL.Path)
		return err
	}

	tokenBytes, err := hex.DecodeString(refreshToken.Value)
	if err != nil {
		ac.loggerService.Error("failed to decode string into bytes", r.URL.Path)
		return err
	}

	err = ac.authService.LogoutUser(ctx, tokenBytes)
	if err != nil {
		if errors.Is(err, context.DeadlineExceeded) {
			ac.loggerService.Info("request timed out", r.URL.Path)
			return commonErrors.NewAPIError(http.StatusRequestTimeout, "")
		}
		return err
	}

	return nil
}

func (ac *AuthController) LogoutUserFromAllDevices(w http.ResponseWriter, r *http.Request) error {
	ctx, cancel := context.WithTimeout(r.Context(), authTimeout)
	defer cancel()

	r, err := ac.authorization.VerifyToken(r)
	if err != nil {
		if errors.Is(err, context.DeadlineExceeded) {
			ac.loggerService.Info("request timed out", r.URL.Path)
			return commonErrors.NewAPIError(http.StatusRequestTimeout, "")
		}
		return err
	}

	userID, err := request.ReadUserIDFromToken(r)
	if err != nil {
		return err
	}

	err = ac.authService.LogoutUserFromAllDevices(ctx, userID)
	if err != nil {
		if errors.Is(err, context.DeadlineExceeded) {
			ac.loggerService.Info("request timed out", r.URL.Path)
			return commonErrors.NewAPIError(http.StatusRequestTimeout, "")
		}
		return err
	}

	return nil
}
