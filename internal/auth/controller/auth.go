// Package controller hold whole logic associated with controller
package controller

import (
	"context"
	"encoding/hex"
	"errors"
	"net/http"
	"os"
	"time"

	commonInterfaces "github.com/slodkiadrianek/MINI-BUCKET/common/interfaces"
	"github.com/slodkiadrianek/MINI-BUCKET/common/middleware"
	authDTO "github.com/slodkiadrianek/MINI-BUCKET/internal/auth/DTO"

	commonErrors "github.com/slodkiadrianek/MINI-BUCKET/common/errors"
	"github.com/slodkiadrianek/MINI-BUCKET/common/request"
	"github.com/slodkiadrianek/MINI-BUCKET/common/response"
)

const authTimeout = 2 * time.Second

type authService interface {
	Register(ctx context.Context, user authDTO.CreateUser) error
	Login(ctx context.Context, loginData authDTO.LoginUser, ipAddress, deviceInfo string) (string, []byte, error)
	RefreshToken(ctx context.Context, token []byte) (string, error)
	LogoutUser(ctx context.Context, refreshToken []byte) error
	LogoutUserFromAllDevices(ctx context.Context, userID int) error
	ActivateAccount(ctx context.Context, userID int) error
}

type AuthController struct {
	loggerService commonInterfaces.Logger
	authService   authService
	authorization commonInterfaces.AuthenticationMiddleware
}

func NewAuthController(loggerService commonInterfaces.Logger, authService authService, authorization commonInterfaces.AuthenticationMiddleware) *AuthController {
	return &AuthController{
		loggerService: loggerService,
		authService:   authService,
		authorization: authorization,
	}
}

func (ac *AuthController) handleTimeout(err error, path string) error {
	if errors.Is(err, context.DeadlineExceeded) {
		ac.loggerService.Info("request timed out", path)
		return commonErrors.NewAPIError(http.StatusRequestTimeout, "")
	}
	return err
}

func (ac *AuthController) Register(w http.ResponseWriter, r *http.Request) error {
	ctx, cancel := context.WithTimeout(r.Context(), authTimeout)
	defer cancel()

	reqData, err := request.ReadBody[authDTO.CreateUser](r)
	if err != nil {
		return commonErrors.NewAPIError(http.StatusUnprocessableEntity, "provided invalid json format")
	}

	err = middleware.ValidateRequestData(reqData)
	if err != nil {
		return err
	}

	err = ac.authService.Register(ctx, *reqData)
	if err != nil {
		return ac.handleTimeout(err, r.URL.Path)
	}

	response.Send(w, http.StatusOK, map[string]string{})
	return nil
}

func (ac *AuthController) Login(w http.ResponseWriter, r *http.Request) error {
	ctx, cancel := context.WithTimeout(r.Context(), authTimeout)
	defer cancel()

	reqData, err := request.ReadBody[authDTO.LoginUser](r)
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
		return ac.handleTimeout(err, r.URL.Path)
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

func (ac *AuthController) readRefreshToken(r *http.Request) ([]byte, error) {
	refreshToken, err := r.Cookie("refreshToken")
	if err != nil {
		ac.loggerService.Error("failed to read cookie from request", err.Error())
		return nil, err
	}

	tokenBytes, err := hex.DecodeString(refreshToken.Value)
	if err != nil {
		ac.loggerService.Error("failed to decode string into bytes", err.Error())
		return nil, err
	}
	return tokenBytes, nil
}

func (ac *AuthController) RefreshToken(w http.ResponseWriter, r *http.Request) error {
	ctx, cancel := context.WithTimeout(r.Context(), authTimeout)
	defer cancel()

	refreshToken, err := ac.readRefreshToken(r)
	if err != nil {
		return err
	}

	newAccessToken, err := ac.authService.RefreshToken(ctx, refreshToken)
	if err != nil {
		return ac.handleTimeout(err, r.URL.Path)
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
		return ac.handleTimeout(err, r.URL.Path)
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
		return ac.handleTimeout(err, r.URL.Path)
	}

	userID, err := request.ReadUserIDFromToken(r)
	if err != nil {
		return err
	}

	err = ac.authService.ActivateAccount(ctx, userID)
	if err != nil {
		return ac.handleTimeout(err, r.URL.Path)
	}

	return nil
}

func (ac *AuthController) LogoutUser(w http.ResponseWriter, r *http.Request) error {
	ctx, cancel := context.WithTimeout(r.Context(), authTimeout)
	defer cancel()

	err := ac.authorization.BlacklistUser(r)
	if err != nil {
		return ac.handleTimeout(err, r.URL.Path)
	}

	refreshToken, err := ac.readRefreshToken(r)
	if err != nil {
		return err
	}

	err = ac.authService.LogoutUser(ctx, refreshToken)
	if err != nil {
		return ac.handleTimeout(err, r.URL.Path)
	}

	return nil
}

func (ac *AuthController) LogoutUserFromAllDevices(w http.ResponseWriter, r *http.Request) error {
	ctx, cancel := context.WithTimeout(r.Context(), authTimeout)
	defer cancel()

	r, err := ac.authorization.VerifyToken(r)
	if err != nil {
		return ac.handleTimeout(err, r.URL.Path)
	}

	userID, err := request.ReadUserIDFromToken(r)
	if err != nil {
		return err
	}

	err = ac.authService.LogoutUserFromAllDevices(ctx, userID)
	if err != nil {
		return ac.handleTimeout(err, r.URL.Path)
	}

	return nil
}
