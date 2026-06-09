package repository

import (
	"context"
	"database/sql"
	"errors"

	commonErrors "github.com/slodkiadrianek/MINI-BUCKET/common/errors"
	commonInterfaces "github.com/slodkiadrianek/MINI-BUCKET/common/interfaces"
	dto "github.com/slodkiadrianek/MINI-BUCKET/internal/objects/DTO"
)

type ObjectRepository struct {
	db            *sql.DB
	loggerService commonInterfaces.Logger
}

func NewObjectRepository(db *sql.DB, loggerService commonInterfaces.Logger) *ObjectRepository {
	return &ObjectRepository{
		db:            db,
		loggerService: loggerService,
	}
}

func (or *ObjectRepository) Create(ctx context.Context, tx *sql.Tx, file dto.Create) (int, error) {
	query := `INSERT INTO objects (
		bucket_id,
		object_key,
		content_type,
		size_bytes,
		etag,
		is_deleted,
		created_at,
		updated_at
	) VALUES ($1,$2,$3,$4,$5,false,NOW(), NOW())`

	stmt, err := tx.PrepareContext(ctx, query)
	if err != nil {
		or.loggerService.Error(commonErrors.FailedToPrepareQuery, map[string]any{
			"query": query,
			"args": map[string]any{
				"bucket_id":    file.BucketID,
				"object_key":   file.ObjectKey,
				"content_type": file.ContentType,
				"size_bytes":   file.SizeBytes,
				"etag":         file.ETag,
			},
			"error": err.Error(),
		})
		return 0, err
	}
	defer func() {
		if closeErr := stmt.Close(); closeErr != nil {
			or.loggerService.Error(commonErrors.FailedToCloseStatement, closeErr)
		}
	}()

	var ObjectID int
	err = stmt.QueryRowContext(ctx, file.BucketID, file.ObjectKey, file.ContentType, file.SizeBytes, file.ETag).Scan(ObjectID)
	if err != nil {
		or.loggerService.Error(commonErrors.FailedToExecuteInsertQuery, map[string]any{
			"query": query,
			"args": map[string]any{
				"bucket_id":    file.BucketID,
				"object_key":   file.ObjectKey,
				"content_type": file.ContentType,
				"size_bytes":   file.SizeBytes,
				"etag":         file.ETag,
			},
			"error": err.Error(),
		})
		return 0, err
	}

	return ObjectID, nil
}

func (or *ObjectRepository) GetNewVersionNumber(ctx context.Context, tx *sql.Tx, objectID int) (int, error) {
	query := `SELECT COALESCE(MAX(version_number), 0) + 1 FROM object_versions WHERE object_id = $1 FOR UPDATE`
	stmt, err := tx.PrepareContext(ctx, query)
	if err != nil {
		or.loggerService.Error(commonErrors.FailedToPrepareQuery, map[string]any{
			"query": stmt,
			"args": map[string]any{
				"object_id": objectID,
			},
			"error": err.Error(),
		})
		return 0, err
	}
	defer func() {
		if closeErr := stmt.Close(); closeErr != nil {
			or.loggerService.Error(commonErrors.FailedToCloseStatement, closeErr)
		}
	}()
	var newVersionNumber int
	err = stmt.QueryRowContext(ctx, objectID).Scan(newVersionNumber)
	if err != nil {
		or.loggerService.Error(commonErrors.FailedToExecuteInsertQuery, map[string]any{
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

func (or *ObjectRepository) CreateVersion(ctx context.Context, file dto.CreateVersion) error {
	tx, err := or.db.BeginTx(ctx, nil)
	if err != nil {
		return err
	}
	defer tx.Rollback()
	query := `INSERT INTO object_versions (
		object_id,
		version_number,
		size_bytes,
		etag,
		storage_class
		created_at,
		updated_at
	) VALUES($1,$2,$3,$4,$5,NOW(), NOW())`

	stmt, err := or.db.PrepareContext(ctx, query)
	if err != nil {
		or.loggerService.Error(commonErrors.FailedToPrepareQuery, map[string]any{
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
		return err
	}
	defer func() {
		if closeErr := stmt.Close(); closeErr != nil {
			or.loggerService.Error(commonErrors.FailedToCloseStatement, closeErr)
		}
	}()

	var ObjectID int
	err = stmt.QueryRowContext(ctx, file.ObjectID, file.VersionNumber, file.SizeBytes, file.ETag, file.StorageClass).Scan(ObjectID)
	if err != nil {
		or.loggerService.Error(commonErrors.FailedToExecuteInsertQuery, map[string]any{
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
		return err
	}

	return nil
}

func (or *ObjectRepository) Exists(ctx context.Context, tx *sql.Tx, objectID int) (bool, error) {
	query := "SELECT id FROM objects WHERE id = $1 FOR UPDATE"
	stmt, err := tx.PrepareContext(ctx, query)
	if err != nil {
		or.loggerService.Error(commonErrors.FailedToPrepareQuery, map[string]any{
			"query": query,
			"args": map[string]any{
				"object_id": objectID,
			},
			"error": err.Error(),
		})
		return false, err
	}

	_, err = stmt.ExecContext(ctx, objectID)
	if err != nil {
		if errors.Is(err, sql.ErrNoRows) {
			return false, nil
		}
		or.loggerService.Error(commonErrors.FailedToExecuteSelectQuery, map[string]any{
			"query": query,
			"args": map[string]any{
				"object_id": objectID,
			},
			"error": err.Error(),
		})
		return false, err
	}
	return true, nil
}
