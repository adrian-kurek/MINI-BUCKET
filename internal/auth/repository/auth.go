package repository

import (
	"context"
	"database/sql"
	"errors"
	"net/http"
	"time"

	authDto "github.com/slodkiadrianek/MINI-BUCKET/internal/auth/DTO"
	"github.com/slodkiadrianek/MINI-BUCKET/internal/auth/model"
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
	query := `INSERT INTO refresh_tokens(user_id,token_hash,device_info,ip_address, expires_at, last_used_at) VALUES($1,$2,$3,$4,$5,$6)`

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
	lastUsedAt := time.Now()

	_, err = stmt.ExecContext(ctx, userID, refreshToken, deviceInfo, ipAddress, expiration, lastUsedAt)
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

func (ar *AuthRepository) GetRefreshTokenByTokenHash(ctx context.Context, refreshToken string) (model.TokenWithUserEmailToRefreshToken, error) {
	query := `
	SELECT 
		rt.id,
		rt.user_id,
		u.email,
		u.username,
		rt.token_hash,
		rt.expires_at 
	FROM refresh_tokens rt
		INNER JOIN users u ON u.id = rt.user_id
	WHERE
		rt.token_hash = $1`

	stmt, err := ar.db.PrepareContext(ctx, query)
	if err != nil {
		ar.loggerService.Error(commonErrors.FailedToPrepareQuery, map[string]string{
			"query": query,
			"error": err.Error(),
		})
		return model.TokenWithUserEmailToRefreshToken{}, err
	}
	defer func() {
		if closeErr := stmt.Close(); closeErr != nil {
			ar.loggerService.Error(commonErrors.FailedToCloseStatement, closeErr)
		}
	}()

	row := stmt.QueryRowContext(ctx, refreshToken)

	var tokenWithUserEmailToRefreshToken model.TokenWithUserEmailToRefreshToken

	err = row.Scan(&tokenWithUserEmailToRefreshToken.ID, &tokenWithUserEmailToRefreshToken.UserID, &tokenWithUserEmailToRefreshToken.Email, &tokenWithUserEmailToRefreshToken.Username, &tokenWithUserEmailToRefreshToken.TokenHash, &tokenWithUserEmailToRefreshToken.ExpiresAt)
	if err != nil {
		if errors.Is(err, sql.ErrNoRows) {
			ar.loggerService.Info("token not found", nil)
			return model.TokenWithUserEmailToRefreshToken{ID: 0}, nil
		}
		ar.loggerService.Error(commonErrors.FailedToPrepareQuery, map[string]string{
			"query": query,
			"error": err.Error(),
		})
		return model.TokenWithUserEmailToRefreshToken{}, err
	}
	return tokenWithUserEmailToRefreshToken, nil
}

func (ar *AuthRepository) UpdateLastTimeUsedToken(ctx context.Context, refreshToken string) error {
	query := `
	UPDATE refresh_tokens SET last_used_at = $1 WHERE token_hash = $2	
	`

	stmt, err := ar.db.PrepareContext(ctx, query)
	if err != nil {
		ar.loggerService.Error(commonErrors.FailedToPrepareQuery, map[string]string{
			"query": query,
			"error": err.Error(),
		})
		return err
	}

	lastUsedAt := time.Now()

	_, err = stmt.ExecContext(ctx, lastUsedAt, refreshToken)
	if err != nil {
		ar.loggerService.Error(commonErrors.FailedToPrepareQuery, map[string]string{
			"query": query,
			"error": err.Error(),
		})
		return err
	}

	return nil
}

func (ar *AuthRepository) RemoveTokenFromDB(ctx context.Context, refreshToken string) error {
	query := "DELETE FROM refresh_tokens WHERE token_hash = $1"

	stmt, err := ar.db.PrepareContext(ctx, query)
	if err != nil {
		ar.loggerService.Error(commonErrors.FailedToPrepareQuery, map[string]string{
			"query": query,
			"error": err.Error(),
		})
		return err
	}

	_, err = stmt.ExecContext(ctx, refreshToken)
	if err != nil {
		ar.loggerService.Error(commonErrors.FailedToPrepareQuery, map[string]string{
			"query": query,
			"error": err.Error(),
		})
		return err
	}

	return nil
}
