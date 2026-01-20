package repository

import (
	"context"
	"database/sql"
	"errors"

	basicErrors "github.com/slodkiadrianek/MINI-BUCKET/internal/common/errors"
	"github.com/slodkiadrianek/MINI-BUCKET/internal/common/interfaces"
	"github.com/slodkiadrianek/MINI-BUCKET/internal/user/model"
)

type UserRepository struct {
	loggerService interfaces.Logger
	db            *sql.DB
}

func NewUserRepository(loggerService interfaces.Logger, db *sql.DB) *UserRepository {
	return &UserRepository{
		loggerService: loggerService,
		db:            db,
	}
}

func (ur *UserRepository) FindUserByEmail(ctx context.Context, email string) (model.User, error) {
	query := "SELECT * FROM USERS WHERE email = $1"
	stmt, err := ur.db.PrepareContext(ctx, query)
	if err != nil {
		ur.loggerService.Error(basicErrors.FailedToPrepareQuery, map[string]string{
			"query": query,
			"error": err.Error(),
		})
		return model.User{}, err
	}
	defer func() {
		if closeErr := stmt.Close(); closeErr != nil {
			ur.loggerService.Error(basicErrors.FailedToCloseStatement, closeErr)
		}
	}()

	var user model.User
	err = stmt.QueryRowContext(ctx, email).Scan(&user.ID, &user.Email, &user.Username, &user.Password, &user.EmailVerified, &user.CreatedAt)
	if err != nil {
		if errors.Is(err, sql.ErrNoRows) {
			ur.loggerService.Info("user not found", map[string]any{
				"email": email,
			})
			return model.User{
				ID: 0,
			}, nil
		}
		ur.loggerService.Error(basicErrors.FailedToExecuteSelectQuery, map[string]any{
			"query": query,
			"args":  []any{email},
			"error": err,
		})
		return model.User{}, errors.New("failed")
	}
	return user, nil
}
