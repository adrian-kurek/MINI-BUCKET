// Package service hold whole loggic associated with service
package service

import (
	"context"
	"errors"
	"fmt"
	"net/http"
	"time"

	authDto "github.com/slodkiadrianek/MINI-BUCKET/internal/auth/DTO"
	"github.com/slodkiadrianek/MINI-BUCKET/internal/auth/model"
	commonErrors "github.com/slodkiadrianek/MINI-BUCKET/internal/common/errors"
	commonInterfaces "github.com/slodkiadrianek/MINI-BUCKET/internal/common/interfaces"
	"github.com/slodkiadrianek/MINI-BUCKET/internal/middleware"
	userModel "github.com/slodkiadrianek/MINI-BUCKET/internal/user/model"
	"golang.org/x/crypto/bcrypt"
)

type authRepository interface {
	RegisterUser(ctx context.Context, user authDto.CreateUser, hashedPassword []byte) error
	InsertRefreshToken(ctx context.Context, ipAddress, deviceInfo, refreshToken string, userID int) error
	GetRefreshTokenByTokenHash(ctx context.Context, refreshToken string) (model.TokenWithUserEmailToRefreshToken, error)
	UpdateLastTimeUsedToken(ctx context.Context, refreshToken string) error
}

type AuthService struct {
	loggerService  commonInterfaces.Logger
	userRepository commonInterfaces.UserRepository
	authRepository authRepository
	authorization  middleware.Authorization
}

func NewAuthService(loggerService commonInterfaces.Logger, userRepository commonInterfaces.UserRepository, authRepository authRepository, authorization middleware.Authorization) *AuthService {
	return &AuthService{
		loggerService:  loggerService,
		userRepository: userRepository,
		authRepository: authRepository,
		authorization:  authorization,
	}
}

func (as *AuthService) Register(ctx context.Context, user authDto.CreateUser) error {
	userFromDB, err := as.userRepository.FindUserByEmail(ctx, user.Email)
	if err != nil {
		return err
	}

	if userFromDB.ID != 0 {
		err := errors.New("user with provided email already exists")
		as.loggerService.Info(err.Error(), user.Email)
		return commonErrors.NewAPIError(http.StatusBadRequest, err.Error())
	}

	hashedPassword, err := bcrypt.GenerateFromPassword([]byte(user.Password), bcrypt.DefaultCost)
	if err != nil {
		as.loggerService.Info(err.Error(), user.Email)
		return err
	}

	err = as.authRepository.RegisterUser(ctx, user, hashedPassword)
	if err != nil {
		return err
	}

	return nil
}

func (as *AuthService) Login(ctx context.Context, loginData authDto.LoginUser, ipAddress, deviceInfo string) (string, []byte, error) {
	userFromDB, err := as.userRepository.FindUserByEmail(ctx, loginData.Email)
	if err != nil {
		return "", nil, err
	}

	if userFromDB.ID == 0 {
		err := errors.New("user with provided email not found")
		as.loggerService.Info(err.Error(), loginData.Email)
		return "", nil, commonErrors.NewAPIError(http.StatusNotFound, err.Error())
	}

	if !userFromDB.EmailVerified {
		err := errors.New("user with provided email is not verified")
		as.loggerService.Info(err.Error(), loginData.Email)
		return "", nil, commonErrors.NewAPIError(http.StatusUnauthorized, err.Error())
	}

	err = bcrypt.CompareHashAndPassword([]byte(userFromDB.Password), []byte(loginData.Password))
	if err != nil {

		err := errors.New("provided incorrect password")
		as.loggerService.Info(err.Error(), loginData.Email)
		return "", nil, commonErrors.NewAPIError(http.StatusUnauthorized, err.Error())
	}

	accessToken, err := as.authorization.GenerateAccessToken(userFromDB)
	if err != nil {
		return "", nil, err
	}

	refreshToken, err := as.authorization.GenerataRefreshToken()
	if err != nil {
		return "", nil, err
	}

	hashedRefreshToken := as.authorization.HashToken(refreshToken)

	err = as.authRepository.InsertRefreshToken(ctx, ipAddress, deviceInfo, hashedRefreshToken, userFromDB.ID)
	if err != nil {
		return "", nil, err
	}

	fmt.Println(string(refreshToken))

	return accessToken, refreshToken, nil
}

func (as *AuthService) RefreshToken(ctx context.Context, token []byte) (string, error) {
	hashedRefreshToken := as.authorization.HashToken(token)

	tokenWithUserEmailToRefreshToken, err := as.authRepository.GetRefreshTokenByTokenHash(ctx, hashedRefreshToken)
	if err != nil {
		return "", err
	}

	if tokenWithUserEmailToRefreshToken.ID == 0 {
		return "", commonErrors.NewAPIError(http.StatusUnauthorized, "token not found")
	}

	if tokenWithUserEmailToRefreshToken.ExpiresAt.Before(time.Now()) {
		err := errors.New("refresh token expired")
		as.loggerService.Info(err.Error(), nil)
		return "", commonErrors.NewAPIError(http.StatusUnauthorized, err.Error())
	}

	err = as.authRepository.UpdateLastTimeUsedToken(ctx, hashedRefreshToken)
	if err != nil {
		return "", err
	}

	user := userModel.User{ID: tokenWithUserEmailToRefreshToken.ID, Email: tokenWithUserEmailToRefreshToken.Email, Username: tokenWithUserEmailToRefreshToken.Username}

	accessToken, err := as.authorization.GenerateAccessToken(user)
	if err != nil {
		return "", nil
	}

	return accessToken, nil
}
