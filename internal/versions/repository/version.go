package repository

import (
	"context"
	"database/sql"

	commonErrors "github.com/slodkiadrianek/MINI-BUCKET/common/errors"
	commonInterfaces "github.com/slodkiadrianek/MINI-BUCKET/common/interfaces"
	dto "github.com/slodkiadrianek/MINI-BUCKET/internal/versions/DTO"
)

type VersionRepository struct {
	db            *sql.DB
	loggerService commonInterfaces.Logger
}

func NewVersionRepository(db *sql.DB, loggerService commonInterfaces.Logger) *VersionRepository {
	return &VersionRepository{
		db:            db,
		loggerService: loggerService,
	}
}

func (ov *VersionRepository) Create(ctx context.Context, tx *sql.Tx, file dto.Create) (int, error) {
	query := `INSERT INTO object_versions (
		object_id,
		version_number,
		size_bytes,
		etag,
		storage_class,
		created_at,
		updated_at
	) VALUES($1,$2,$3,$4,$5,NOW(), NOW()) RETURNING id`

	stmt, err := tx.PrepareContext(ctx, query)
	if err != nil {
		ov.loggerService.Error(commonErrors.FailedToPrepareQuery, map[string]any{
			"query": query,
			"args": map[string]any{
				"object_id":      file.ObjectID,
				"version_number": file.VersionNumber,
				"size_bytes":     file.SizeBytes,
				"etag":           file.ETag,
				"storage_class":  file.StorageClass,
			},
			"error": err.Error(),
		})
		return 0, err
	}
	defer func() {
		if closeErr := stmt.Close(); closeErr != nil {
			ov.loggerService.Error(commonErrors.FailedToCloseStatement, closeErr)
		}
	}()

	var newVersionID int
	err = stmt.QueryRowContext(ctx, file.ObjectID, file.VersionNumber, file.SizeBytes, file.ETag, file.StorageClass).Scan(&newVersionID)
	if err != nil {
		ov.loggerService.Error(commonErrors.FailedToExecuteInsertQuery, map[string]any{
			"query": query,
			"args": map[string]any{
				"object_id":      file.ObjectID,
				"version_number": file.VersionNumber,
				"size_bytes":     file.SizeBytes,
				"etag":           file.ETag,
				"storage_class":  file.StorageClass,
			},
			"error": err.Error(),
		})
		return 0, err
	}

	return newVersionID, nil
}

func (ov *VersionRepository) GetNewVersionNumber(ctx context.Context, tx *sql.Tx, objectID int) (int, error) {
	query := `SELECT COALESCE(MAX(version_number), 0) + 1 as new_version_num FROM object_versions WHERE object_id = $1  `
	stmt, err := tx.PrepareContext(ctx, query)
	if err != nil {
		ov.loggerService.Error(commonErrors.FailedToPrepareQuery, map[string]any{
			"query": query,
			"args": map[string]any{
				"object_id": objectID,
			},
			"error": err.Error(),
		})
		return 0, err
	}
	defer func() {
		if closeErr := stmt.Close(); closeErr != nil {
			ov.loggerService.Error(commonErrors.FailedToCloseStatement, closeErr)
		}
	}()
	var newVersionNumber int
	err = stmt.QueryRowContext(ctx, objectID).Scan(&newVersionNumber)
	if err != nil {
		ov.loggerService.Error(commonErrors.FailedToExecuteInsertQuery, map[string]any{
			"query": query,
			"args": map[string]any{
				"object_id": objectID,
			},
			"error": err.Error(),
		})
		return 0, err
	}

	return newVersionNumber, nil
}
