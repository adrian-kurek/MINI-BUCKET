// Package service hold whole loggic associated with service
package service

import (
	"context"
	"errors"
	"net/http"

	authDto "github.com/slodkiadrianek/MINI-BUCKET/internal/auth/DTO"
	commonErrors "github.com/slodkiadrianek/MINI-BUCKET/internal/common/errors"
	commonInterfaces "github.com/slodkiadrianek/MINI-BUCKET/internal/common/interfaces"
	"github.com/slodkiadrianek/MINI-BUCKET/internal/middleware"
	"golang.org/x/crypto/bcrypt"
)

type authRepository interface {
	RegisterUser(ctx context.Context, user authDto.CreateUser, hashedPassword []byte) error
	InsertRefreshToken(ctx context.Context, ipAddress, deviceInfo, refreshToken string, userID int) error
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

func (as *AuthService) Login(ctx context.Context, loginData authDto.LoginUser, ipAddress, deviceInfo string) (string, string, error) {
	userFromDB, err := as.userRepository.FindUserByEmail(ctx, loginData.Email)
	if err != nil {
		return "", "", err
	}

	if userFromDB.ID == 0 {
		err := errors.New("user with provided email not found")
		as.loggerService.Info(err.Error(), loginData.Email)
		return "", "", commonErrors.NewAPIError(http.StatusNotFound, err.Error())
	}

	if !userFromDB.EmailVerified {
		err := errors.New("user with provided email is not verified")
		as.loggerService.Info(err.Error(), loginData.Email)
		return "", "", commonErrors.NewAPIError(http.StatusUnauthorized, err.Error())
	}

	err = bcrypt.CompareHashAndPassword([]byte(userFromDB.Password), []byte(loginData.Password))
	if err != nil {

		err := errors.New("provided incorrect password")
		as.loggerService.Info(err.Error(), loginData.Email)
		return "", "", commonErrors.NewAPIError(http.StatusUnauthorized, err.Error())
	}

	accessToken, err := as.authorization.GenerateAccessToken(userFromDB)
	if err != nil {
		return "", "", err
	}

	refreshToken, err := as.authorization.GenerataRefreshToken()
	if err != nil {
		return "", "", err
	}

	err = as.authRepository.InsertRefreshToken(ctx, ipAddress, deviceInfo, refreshToken, userFromDB.ID)
	if err != nil {
		return "", "", err
	}

	return accessToken, refreshToken, nil
}
