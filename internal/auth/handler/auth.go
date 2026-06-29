// Pahkage controller hold whole logic associated with controller
package controller

import (
	"context"
	"encoding/hex"
	"errors"
	"net/http"
	"os"
	"time"

	commonInterfaces "github.com/slodkiadrianek/MINI-BUCKET/common/interfaces"
	commonInterfahes "github.com/slodkiadrianek/MINI-BUCKET/common/interfaces"
	"github.com/slodkiadrianek/MINI-BUCKET/common/middleware"
	authDTO "github.com/slodkiadrianek/MINI-BUCKET/internal/auth/DTO"

	commonErrors "github.com/slodkiadrianek/MINI-BUCKET/common/errors"
	"github.com/slodkiadrianek/MINI-BUCKET/common/request"
	"github.com/slodkiadrianek/MINI-BUCKET/common/response"
)

const authTimeout = 2 * time.Second

type AuthService interface {
	Register(ctx context.Context, user authDTO.CreateUser) error
	Login(ctx context.Context, loginData authDTO.LoginUser, ipAddress, deviceInfo string) (string, []byte, error)
	RefreshToken(ctx context.Context, token []byte) (string, error)
	LogoutUser(ctx context.Context, refreshToken []byte) error
	LogoutUserFromAllDevices(ctx context.Context, userID int) error
	ActivateAccount(ctx context.Context, userID int) error
}

type AuthHandler struct {
	loggerService commonInterfahes.Logger
	authService   AuthService
	authorization commonInterfahes.AuthenticationMiddleware
}

func NewAuthHandler(
	loggerService commonInterfahes.Logger,
	authService AuthService,
	authorization commonInterfaces.AuthenticationMiddleware,
) *AuthHandler {
	return &AuthHandler{
		loggerService: loggerService,
		authService:   authService,
		authorization: authorization,
	}
}

func (ah *AuthHandler) handleTimeout(err error, path string) error {
	if errors.Is(err, context.DeadlineExceeded) {
		ah.loggerService.Info("request timed out", path)
		return commonErrors.NewAPIError(http.StatusRequestTimeout, "")
	}
	return err
}

func (ah *AuthHandler) Register(w http.ResponseWriter, r *http.Request) error {
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

	err = ah.authService.Register(ctx, *reqData)
	if err != nil {
		return ah.handleTimeout(err, r.URL.Path)
	}

	response.Send(w, http.StatusOK, map[string]string{})
	return nil
}

func (ah *AuthHandler) Login(w http.ResponseWriter, r *http.Request) error {
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

	accessToken, refreshToken, err := ah.authService.Login(ctx, *reqData, ipAddress, deviceInfo)
	if err != nil {
		return ah.handleTimeout(err, r.URL.Path)
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

func (ah *AuthHandler) readRefreshToken(r *http.Request) ([]byte, error) {
	refreshToken, err := r.Cookie("refreshToken")
	if err != nil {
		ah.loggerService.Error("failed to read cookie from request", err.Error())
		return nil, err
	}

	tokenBytes, err := hex.DecodeString(refreshToken.Value)
	if err != nil {
		ah.loggerService.Error("failed to decode string into bytes", err.Error())
		return nil, err
	}
	return tokenBytes, nil
}

func (ah *AuthHandler) RefreshToken(w http.ResponseWriter, r *http.Request) error {
	ctx, cancel := context.WithTimeout(r.Context(), authTimeout)
	defer cancel()

	refreshToken, err := ah.readRefreshToken(r)
	if err != nil {
		return err
	}

	newaccessToken, err := ah.authService.RefreshToken(ctx, refreshToken)
	if err != nil {
		return ah.handleTimeout(err, r.URL.Path)
	}

	response.Send(w, http.StatusOK, map[string]string{"token": newaccessToken})

	return nil
}

func (ah *AuthHandler) Verify(w http.ResponseWriter, r *http.Request) error {
	ctx, cancel := context.WithTimeout(r.Context(), authTimeout)
	defer cancel()

	r = r.WithContext(ctx)

	r, err := ah.authorization.VerifyToken(r)
	if err != nil {
		return ah.handleTimeout(err, r.URL.Path)
	}

	response.Send(w, http.StatusNoContent, nil)

	return nil
}

func (ah *AuthHandler) ActivateAccount(w http.ResponseWriter, r *http.Request) error {
	ctx, cancel := context.WithTimeout(r.Context(), authTimeout)
	defer cancel()

	r = r.WithContext(ctx)

	authToken := request.ReadQueryParam(r, "token")
	r.Header.Set("Authorization", "Bearer "+authToken)

	r, err := ah.authorization.VerifyToken(r)
	if err != nil {
		return ah.handleTimeout(err, r.URL.Path)
	}

	userID, err := request.ReadUserIDFromToken(r)
	if err != nil {
		return err
	}

	err = ah.authService.ActivateAccount(ctx, userID)
	if err != nil {
		return ah.handleTimeout(err, r.URL.Path)
	}

	response.Send(w, http.StatusNoContent, nil)

	return nil
}

func (ah *AuthHandler) LogoutUser(w http.ResponseWriter, r *http.Request) error {
	ctx, cancel := context.WithTimeout(r.Context(), authTimeout)
	defer cancel()

	err := ah.authorization.BlacklistUser(r)
	if err != nil {
		return ah.handleTimeout(err, r.URL.Path)
	}

	refreshToken, err := ah.readRefreshToken(r)
	if err != nil {
		return err
	}

	err = ah.authService.LogoutUser(ctx, refreshToken)
	if err != nil {
		return ah.handleTimeout(err, r.URL.Path)
	}

	response.Send(w, http.StatusNoContent, nil)
	return nil
}

func (ah *AuthHandler) LogoutUserFromAllDevices(w http.ResponseWriter, r *http.Request) error {
	ctx, cancel := context.WithTimeout(r.Context(), authTimeout)
	defer cancel()

	r, err := ah.authorization.VerifyToken(r)
	if err != nil {
		return ah.handleTimeout(err, r.URL.Path)
	}

	userID, err := request.ReadUserIDFromToken(r)
	if err != nil {
		return err
	}

	err = ah.authService.LogoutUserFromAllDevices(ctx, userID)
	if err != nil {
		return ah.handleTimeout(err, r.URL.Path)
	}

	response.Send(w, http.StatusNoContent, nil)
	return nil
}
