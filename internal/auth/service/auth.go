// Package service hold whole loggic associated with service
package service

import (
	"context"
	"errors"

	dto "github.com/slodkiadrianek/MINI-BUCKET/internal/auth/DTO"
	"github.com/slodkiadrianek/MINI-BUCKET/internal/common/interfaces"
	"golang.org/x/crypto/bcrypt"
)

type authRepository interface {
	RegisterUser(ctx context.Context, user dto.CreateUser, hashedPassword []byte) error
}

type AuthService struct {
	loggerService  interfaces.Logger
	userRepository interfaces.UserRepository
	authRepository authRepository
}

func NewAuthService(loggerService interfaces.Logger, userRepository interfaces.UserRepository, authRepository authRepository) *AuthService {
	return &AuthService{
		loggerService:  loggerService,
		userRepository: userRepository,
		authRepository: authRepository,
	}
}

func (as *AuthService) Register(ctx context.Context, user dto.CreateUser) error {
	userFromDB, err := as.userRepository.FindUserByEmail(ctx, user.Email)
	if err != nil {
		return err
	}

	if userFromDB.ID != 0 {
		as.loggerService.Info("user with provided email already exists", user.Email)
		return errors.New("test")
	}

	hashedPassword, err := bcrypt.GenerateFromPassword([]byte(user.Password), bcrypt.MaxCost)
	if err != nil {
		as.loggerService.Error("failed to hash password", err)
		return err
	}

	err = as.authRepository.RegisterUser(ctx, user, hashedPassword)
	if err != nil {
		return err
	}

	return nil
}
