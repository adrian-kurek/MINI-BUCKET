// Package service hold whole loggic associated with service
package service

import (
	"context"
	"errors"
	"fmt"

	authDto "github.com/slodkiadrianek/MINI-BUCKET/internal/auth/DTO"
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
		fmt.Println(err.Error())
		return err
	}

	if userFromDB.ID != 0 {
		as.loggerService.Info("user with provided email already exists", user.Email)
		return errors.New("test")
	}

	hashedPassword, err := bcrypt.GenerateFromPassword([]byte(user.Password), bcrypt.DefaultCost)
	if err != nil {
		as.loggerService.Error("failed to hash password", err)
		return err
	}
	fmt.Println("tes")

	err = as.authRepository.RegisterUser(ctx, user, hashedPassword)
	if err != nil {
		return err
	}

	return nil
}
