package repository

import (
	"context"
	"database/sql"
	"net/http"
	"time"

	authDto "github.com/slodkiadrianek/MINI-BUCKET/internal/auth/DTO"
	commonErrors "github.com/slodkiadrianek/MINI-BUCKET/internal/common/errors"
	commonInterfaces "github.com/slodkiadrianek/MINI-BUCKET/internal/common/interfaces"
)

type AuthRepository struct {
	loggerService commonInterfaces.Logger
	db            *sql.DB
}

func NewAuthRepository(loggerService commonInterfaces.Logger, db *sql.DB) *AuthRepository {
	return &AuthRepository{
		loggerService: loggerService,
		db:            db,
	}
}

func (ar *AuthRepository) RegisterUser(ctx context.Context, user authDto.CreateUser, hashedPassword []byte) error {
	query := `INSERT INTO users (email,username,password,created_at) VALUES ($1,$2,$3,$4)`

	stmt, err := ar.db.PrepareContext(ctx, query)
	if err != nil {
		ar.loggerService.Error(commonErrors.FailedToPrepareQuery, map[string]string{
			"query": query,
			"error": err.Error(),
		})
		return err
	}
	defer func() {
		if closeErr := stmt.Close(); closeErr != nil {
			ar.loggerService.Error(commonErrors.FailedToCloseStatement, closeErr)
		}
	}()

	timestamp := time.Now()

	_, err = stmt.ExecContext(ctx, user.Email, user.Username, hashedPassword, timestamp)
	if err != nil {
		ar.loggerService.Error(commonErrors.FailedToExecuteInsertQuery, map[string]any{
			"query": query,
			"args": map[string]string{
				"username": user.Username,
				"email":    user.Email,
			},
			"error": err,
		})
		return commonErrors.NewAPIError(http.StatusBadRequest, "failed to register a new user")
	}

	return nil
}

func (ar *AuthRepository) InsertRefreshToken(ctx context.Context, ipAddress, deviceInfo, refreshToken string, userID int) error {
	query := `INSERT INTO refresh_tokens(user_id,token_hash,device_info,ip_address, expires_at) VALUES($1,$2,$3,$4, $5)`

	stmt, err := ar.db.PrepareContext(ctx, query)
	if err != nil {
		ar.loggerService.Error(commonErrors.FailedToPrepareQuery, map[string]string{
			"query": query,
			"error": err.Error(),
		})
		return err
	}
	defer func() {
		if closeErr := stmt.Close(); closeErr != nil {
			ar.loggerService.Error(commonErrors.FailedToCloseStatement, closeErr)
		}
	}()

	expiration := time.Now().Add(7 * 24 * time.Hour)

	_, err = stmt.ExecContext(ctx, userID, refreshToken, deviceInfo, ipAddress, expiration)
	if err != nil {
		ar.loggerService.Error(commonErrors.FailedToExecuteInsertQuery, map[string]any{
			"query": query,
			"args": map[string]any{
				"userId":     userID,
				"deviceInfo": deviceInfo,
				"ipAddress":  ipAddress,
			},
			"error": err,
		})
		return commonErrors.NewAPIError(http.StatusBadRequest, "failed to authorize a user")
	}

	return nil
}
