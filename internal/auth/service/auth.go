package service

import "github.com/slodkiadrianek/MINI-BUCKET/internal/interfaces"

type AuthService struct {
	loggerService interfaces.Logger
}

func NewAuthService(loggerService interfaces.Logger) *AuthService {
	return &AuthService{
		loggerService: loggerService,
	}
}
