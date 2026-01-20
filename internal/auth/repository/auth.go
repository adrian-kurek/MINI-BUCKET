package repository

import (
	"database/sql"

	dto "github.com/slodkiadrianek/MINI-BUCKET/internal/auth/DTO"
	"github.com/slodkiadrianek/MINI-BUCKET/internal/common/interfaces"
)

type AuthRepository struct {
	loggerService interfaces.Logger
	db            *sql.DB
}

func NewAuthRepository(loggerService interfaces.Logger, db *sql.DB) *AuthRepository {
	return &AuthRepository{
		loggerService: loggerService,
		db:            db,
	}
}

// func (ar *AuthRepository) RegisterUser(user dto.CreateUser) error {
// }
