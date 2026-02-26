// Package service hold whole loggic associated with service
package service

import (
	"context"
	"errors"
	"net/http"
	"os"
	"time"

	authDto "github.com/slodkiadrianek/MINI-BUCKET/internal/auth/DTO"
	authModel "github.com/slodkiadrianek/MINI-BUCKET/internal/auth/model"
	commonErrors "github.com/slodkiadrianek/MINI-BUCKET/internal/common/errors"
	commonInterfaces "github.com/slodkiadrianek/MINI-BUCKET/internal/common/interfaces"
	userModel "github.com/slodkiadrianek/MINI-BUCKET/internal/user/model"
	"golang.org/x/crypto/bcrypt"
)

type authRepository interface {
	RegisterUser(ctx context.Context, user authDto.CreateUser, hashedPassword []byte) error
	InsertRefreshToken(ctx context.Context, ipAddress, deviceInfo, refreshToken string, userID int) error
	GetRefreshTokenByTokenHash(ctx context.Context, refreshToken string) (authModel.TokenWithUserEmailToRefreshToken, error)
	UpdateLastTimeUsedToken(ctx context.Context, refreshToken string) error
	RemoveTokenFromDB(ctx context.Context, refreshToken string) error
	RemoveTokensFromDBByUserID(ctx context.Context, userID int) error
	ActivateAccount(ctx context.Context, userID int) error
}

type emailService interface {
	SendEmail(to, subject, body string) error
}

type AuthService struct {
	loggerService  commonInterfaces.Logger
	userRepository commonInterfaces.UserRepository
	authRepository authRepository
	authorization  commonInterfaces.AuthorizationMiddleware
	emailService   emailService
}

func NewAuthService(loggerService commonInterfaces.Logger, userRepository commonInterfaces.UserRepository, authRepository authRepository, authorization commonInterfaces.AuthorizationMiddleware, emailService emailService) *AuthService {
	return &AuthService{
		loggerService:  loggerService,
		userRepository: userRepository,
		authRepository: authRepository,
		authorization:  authorization,
		emailService:   emailService,
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
		as.loggerService.Info(err.Error(), nil)
		return err
	}

	if err := ctx.Err(); err != nil {
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
		userAuthData := userModel.User{
			ID:       userFromDB.ID,
			Email:    userFromDB.Email,
			Username: userFromDB.Username,
		}

		accessToken, err := as.authorization.GenerateAccessToken(userAuthData)
		if err != nil {
			return "", nil, err
		}

		host := os.Getenv("HOST_LINK")
		err = as.emailService.SendEmail(loginData.Email, "activation link", host+"/auth/activateAccount?token="+accessToken)
		if err != nil {
			return "", nil, err
		}

		err = errors.New("user with provided email is not verified, we sent to you mail with activation link")
		as.loggerService.Info(err.Error(), loginData.Email)
		return "", nil, commonErrors.NewAPIError(http.StatusUnauthorized, err.Error())
	}

	err = bcrypt.CompareHashAndPassword([]byte(userFromDB.Password), []byte(loginData.Password))
	if err != nil {
		err := errors.New("provided incorrect password")
		as.loggerService.Info(err.Error(), loginData.Email)
		return "", nil, commonErrors.NewAPIError(http.StatusUnauthorized, err.Error())

	}

	if err := ctx.Err(); err != nil {
		return "", nil, err
	}

	accessToken, err := as.authorization.GenerateAccessToken(userFromDB)
	if err != nil {
		return "", nil, err
	}

	refreshToken, err := as.authorization.GenerateRefreshToken()
	if err != nil {
		return "", nil, err
	}

	hashedRefreshToken := as.authorization.HashToken(refreshToken)

	if err := ctx.Err(); err != nil {
		return "", nil, err
	}

	err = as.authRepository.InsertRefreshToken(ctx, ipAddress, deviceInfo, hashedRefreshToken, userFromDB.ID)
	if err != nil {
		return "", nil, err
	}

	return accessToken, refreshToken, nil
}

func (as *AuthService) ActivateAccount(ctx context.Context, userID int) error {
	err := as.authRepository.ActivateAccount(ctx, userID)
	if err != nil {
		return err
	}

	return nil
}

func (as *AuthService) RefreshToken(ctx context.Context, refreshToken []byte) (string, error) {
	hashedRefreshToken := as.authorization.HashToken(refreshToken)

	tokenWithUserEmailToRefreshToken, err := as.authRepository.GetRefreshTokenByTokenHash(ctx, hashedRefreshToken)
	if err != nil {
		return "", err
	}

	if tokenWithUserEmailToRefreshToken.ID == 0 {
		err := errors.New("token not found")
		as.loggerService.Info(err.Error(), nil)
		return "", commonErrors.NewAPIError(http.StatusUnauthorized, err.Error())
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
		return "", err
	}

	return accessToken, nil
}

func (as *AuthService) LogoutUser(ctx context.Context, refreshToken []byte) error {
	hashedRefreshToken := as.authorization.HashToken(refreshToken)

	err := as.authRepository.RemoveTokenFromDB(ctx, hashedRefreshToken)
	if err != nil {
		return err
	}

	return nil
}

func (as *AuthService) LogoutUserFromAllDevices(ctx context.Context, userID int) error {
	err := as.authRepository.RemoveTokensFromDBByUserID(ctx, userID)
	if err != nil {
		return err
	}

	return nil
}
