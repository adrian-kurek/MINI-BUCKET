package repository

import "github.com/slodkiadrianek/MINI-BUCKET/internal/interfaces"

type AuthRepository struct {
	loggerService interfaces.Logger
}

func NewAuthRepository(loggerService interfaces.Logger) *AuthRepository {
	return &AuthRepository{
		loggerService: loggerService,
	}
}
