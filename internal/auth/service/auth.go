package service

import (
	"context"

	"github.com/slodkiadrianek/MINI-BUCKET/internal/common/interfaces"
	"github.com/slodkiadrianek/MINI-BUCKET/internal/user/model"
)

type AuthService struct {
	loggerService  interfaces.Logger
	userRepository interfaces.UserRepository
}

func NewAuthService(loggerService interfaces.Logger, userRepository interfaces.UserRepository) *AuthService {
	return &AuthService{
		loggerService:  loggerService,
		userRepository: userRepository,
	}
}

func (as *AuthService) Register(ctx context.Context, user model.User) error {
	// _, err := as.userRepository.FindUserByEmail(ctx, user.Email)
	// if err != nil {
	// 	return err
	// }
	return nil
}
