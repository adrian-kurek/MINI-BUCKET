package repository

import (
	"context"
	"database/sql"
	"errors"
	"time"

	dto "github.com/slodkiadrianek/MINI-BUCKET/internal/auth/DTO"
	basicErrors "github.com/slodkiadrianek/MINI-BUCKET/internal/common/errors"
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

func (ar *AuthRepository) RegisterUser(ctx context.Context, user dto.CreateUser, hashedPassword []byte) error {
	query := `INSERT INTO users VALUES(email,username,password,created_at) VALUES ($1,$2,$3,$4)`

	stmt, err := ar.db.PrepareContext(ctx, query)
	if err != nil {
		ar.loggerService.Error(basicErrors.FailedToPrepareQuery, map[string]string{
			"query": query,
			"error": err.Error(),
		})
		return err
	}
	defer func() {
		if closeErr := stmt.Close(); closeErr != nil {
			ar.loggerService.Error(basicErrors.FailedToCloseStatement, closeErr)
		}
	}()

	timestamp := time.Now()

	_, err = stmt.ExecContext(ctx, user.Email, user.Username, hashedPassword, timestamp)
	if err != nil {
		ar.loggerService.Error(basicErrors.FailedToExecuteInsertQuery, map[string]any{
			"query": query,
			"args":  user,
			"error": err,
		})
		return errors.New("failed")
	}

	return nil
}
