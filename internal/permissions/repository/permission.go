package repository

import (
	"context"
	"database/sql"

	commonErrors "github.com/slodkiadrianek/MINI-BUCKET/common/errors"
	commonInterfaces "github.com/slodkiadrianek/MINI-BUCKET/common/interfaces"
)

type PermissionRepository struct {
	logger commonInterfaces.Logger
	db     *sql.DB
}

func NewPermissionRepository(logger commonInterfaces.Logger, db *sql.DB) *PermissionRepository {
	return &PermissionRepository{
		logger: logger,
		db:     db,
	}
}

func (pr *PermissionRepository) Create(ctx context.Context, bucketID, userID, permission int) (int, error) {
	query := `INSERT INTO bucket_permissions (bucket_id,user_id,permission,created_at,updated_at) VALUES ($1, $2, $3, NOW(), NOW())`
	stmt, err := pr.db.PrepareContext(ctx, query)
	if err != nil {
		pr.logger.Error(commonErrors.FailedToPrepareQuery, map[string]any{
			"query": query,
			"args": map[string]any{
				"bucket_id":  bucketID,
				"user_id":    userID,
				"permission": permission,
			},
			"error": err.Error(),
		})
		return 0, err
	}
	defer func() {
		if closeErr := stmt.Close(); closeErr != nil {
			pr.logger.Error(commonErrors.FailedToCloseStatement, closeErr)
		}
	}()

	var bucketPermissionID int
	err = stmt.QueryRowContext(ctx, bucketID, userID, permission).Scan(&bucketPermissionID)
	if err != nil {
		pr.logger.Error(commonErrors.FailedToExecuteInsertQuery, map[string]any{
			"query": query,
			"args": map[string]any{
				"bucket_id":  bucketID,
				"user_id":    userID,
				"permission": permission,
			},
			"error": err.Error(),
		})
		return 0, err
	}

	return bucketPermissionID, nil
}

func (pr *PermissionRepository) GetPermissionValByUserID(ctx context.Context, bucketID, userID int) (int, error) {
	query := `SELECT id, permission FROM bucket_permissions WHERE bucket_id = $1 AND user_id = $2`
	stmt, err := pr.db.PrepareContext(ctx, query)
	if err != nil {
		pr.logger.Error(commonErrors.FailedToPrepareQuery, map[string]any{
			"query": query,
			"args": map[string]any{
				"bucket_id": bucketID,
				"user_id":   userID,
			},
			"error": err.Error(),
		})
		return 0, err
	}
	defer func() {
		if closeErr := stmt.Close(); closeErr != nil {
			pr.logger.Error(commonErrors.FailedToCloseStatement, closeErr)
		}
	}()

	var permission int
	var permissionID int
	err = stmt.QueryRowContext(ctx, bucketID, userID).Scan(&permissionID, &permission)
	if err != nil {
		pr.logger.Error(commonErrors.FailedToExecuteSelectQuery, map[string]any{
			"query": query,
			"args": map[string]any{
				"bucket_id": bucketID,
				"user_id":   userID,
			},
			"error": err.Error(),
		})
		return 0, err
	}

	return permission, nil
}

func (pr *PermissionRepository) Update(ctx context.Context, permissionID, bucketID, userID, permission int) error {
	query := `UPDATE bucket_permissions SET permission = $1 WHERE id = $2 AND bucket_id = $3 AND user_id = $4`
	stmt, err := pr.db.PrepareContext(ctx, query)
	if err != nil {
		pr.logger.Error(commonErrors.FailedToPrepareQuery, map[string]any{
			"query": query,
			"args": map[string]any{
				"permission_id": permissionID,
				"bucket_id":     bucketID,
				"user_id":       userID,
				"permission":    permission,
			},
			"error": err.Error(),
		})
		return err
	}
	defer func() {
		if closeErr := stmt.Close(); closeErr != nil {
			pr.logger.Error(commonErrors.FailedToCloseStatement, closeErr)
		}
	}()

	_, err = stmt.ExecContext(ctx, permission, permissionID, bucketID, userID)
	if err != nil {
		pr.logger.Error(commonErrors.FailedToExecuteUpdateQuery, map[string]any{
			"query": query,
			"args": map[string]any{
				"permission_id": permissionID,
				"bucket_id":     bucketID,
				"user_id":       userID,
				"permission":    permission,
			},
			"error": err.Error(),
		})
		return err
	}

	return nil
}

func (pr *PermissionRepository) Delete(ctx context.Context, permissionID, bucketID, userID int) error {
	query := `DELETE FROM bucket_permissions  WHERE id = $1 AND bucket_id = $2 AND user_id = $3`
	stmt, err := pr.db.PrepareContext(ctx, query)
	if err != nil {
		pr.logger.Error(commonErrors.FailedToPrepareQuery, map[string]any{
			"query": query,
			"args": map[string]any{
				"permission_id": permissionID,
				"bucket_id":     bucketID,
				"user_id":       userID,
			},
			"error": err.Error(),
		})
		return err
	}
	defer func() {
		if closeErr := stmt.Close(); closeErr != nil {
			pr.logger.Error(commonErrors.FailedToCloseStatement, closeErr)
		}
	}()

	_, err = stmt.ExecContext(ctx, permissionID, bucketID, userID)
	if err != nil {
		pr.logger.Error(commonErrors.FailedToExecuteDeleteQuery, map[string]any{
			"query": query,
			"args": map[string]any{
				"permission_id": permissionID,
				"bucket_id":     bucketID,
				"user_id":       userID,
			},
			"error": err.Error(),
		})
		return err
	}

	return nil
}
