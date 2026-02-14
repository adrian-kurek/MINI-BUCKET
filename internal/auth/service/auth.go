// Package service hold whole loggic associated with service
package service

import (
	"context"
	"errors"
	"net/http"

	authDto "github.com/slodkiadrianek/MINI-BUCKET/internal/auth/DTO"
	commonErrors "github.com/slodkiadrianek/MINI-BUCKET/internal/common/errors"
	commonInterfaces "github.com/slodkiadrianek/MINI-BUCKET/internal/common/interfaces"
	"golang.org/x/crypto/bcrypt"
)

type authRepository interface {
	RegisterUser(ctx context.Context, user authDto.CreateUser, hashedPassword []byte) error
}

type AuthService struct {
	loggerService  commonInterfaces.Logger
	userRepository commonInterfaces.UserRepository
	authRepository authRepository
}

func NewAuthService(loggerService commonInterfaces.Logger, userRepository commonInterfaces.UserRepository, authRepository authRepository) *AuthService {
	return &AuthService{
		loggerService:  loggerService,
		userRepository: userRepository,
		authRepository: authRepository,
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
