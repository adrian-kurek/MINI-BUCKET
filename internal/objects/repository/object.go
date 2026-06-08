package repository

import (
	"context"
	"database/sql"

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

func (or *ObjectRepository) Create(ctx context.Context, file dto.Create) error {
	query := `INSERT INTO objects (
		bucket_id,
		object_key,
		content_type,
		size_bytes,
		etag,
		current_version_id,
		is_deleted,
		created_at,
		updated_at
	) VALUES($1,$2,$3,$4,$5,$6,false,NOW(), NOW())`

	stmt, err := or.db.PrepareContext(ctx, query)
	if err != nil {
		or.loggerService.Error(commonErrors.FailedToPrepareQuery, map[string]any{
			"query": query,
			"args": map[string]any{
				"bucket_id":          file.BuckeID,
				"object_key":         file.ObjectKey,
				"content_type":       file.ContentType,
				"size_bytes":         file.SizeBytes,
				"etag":               file.ETag,
				"current_version_id": file.CurrentVersionID,
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
	err = stmt.QueryRowContext(ctx, file.BuckeID, file.ObjectKey, file.ContentType, file.SizeBytes, file.ETag, file.CurrentVersionID).Scan(ObjectID)
	if err != nil {
		or.loggerService.Error(commonErrors.FailedToExecuteInsertQuery, map[string]any{
			"query": query,
			"args": map[string]any{
				"bucket_id":          file.BuckeID,
				"object_key":         file.ObjectKey,
				"content_type":       file.ContentType,
				"size_bytes":         file.SizeBytes,
				"etag":               file.ETag,
				"current_version_id": file.CurrentVersionID,
			},
			"error": err.Error(),
		})
		return err
	}

	return nil
}

func (or *ObjectRepository) CreateVersion(ctx context.Context, file dto.Create) error {
	tx, err := or.db.BeginTx(ctx, nil)
	if err != nil {
		return err
	}
	defer tx.Rollback()
	getVersionNumberQuery := `SELECT COALESCE(MAX(version_number), 0) + 1 FROM object_versions WHERE object_id = $1 FOR UPDATE`
	stmtGetVersionNumber, err := or.db.PrepareContext(ctx, getVersionNumberQuery)
	if err != nil {
		or.loggerService.Error(commonErrors.FailedToPrepareQuery, map[string]any{
			"query": stmtGetVersionNumber,
			"args": map[string]any{
				"object_id":          file.BuckeID,
				"object_key":         file.ObjectKey,
				"content_type":       file.ContentType,
				"size_bytes":         file.SizeBytes,
				"etag":               file.ETag,
				"current_version_id": file.CurrentVersionID,
			},
			"error": err.Error(),
		})
		return err
	}
	defer func() {
		if closeErr := stmtGetVersionNumber.Close(); closeErr != nil {
			or.loggerService.Error(commonErrors.FailedToCloseStatement, closeErr)
		}
	}()
	var versionNumber int
	query := `INSERT INTO objects (
		object_id,
		version_number,
		is_latest,
		size_bytes,
		etag,
		storage_class
		created_at,
		updated_at
	) VALUES($1,$2,true,$3,$4,$5,NOW(), NOW())`

	stmt, err := or.db.PrepareContext(ctx, query)
	if err != nil {
		or.loggerService.Error(commonErrors.FailedToPrepareQuery, map[string]any{
			"query": query,
			"args": map[string]any{
				"bucket_id":          file.BuckeID,
				"object_key":         file.ObjectKey,
				"content_type":       file.ContentType,
				"size_bytes":         file.SizeBytes,
				"etag":               file.ETag,
				"current_version_id": file.CurrentVersionID,
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
	err = stmt.QueryRowContext(ctx, file.BuckeID, file.ObjectKey, file.ContentType, file.SizeBytes, file.ETag, file.CurrentVersionID).Scan(ObjectID)
	if err != nil {
		or.loggerService.Error(commonErrors.FailedToExecuteInsertQuery, map[string]any{
			"query": query,
			"args": map[string]any{
				"bucket_id":          file.BuckeID,
				"object_key":         file.ObjectKey,
				"content_type":       file.ContentType,
				"size_bytes":         file.SizeBytes,
				"etag":               file.ETag,
				"current_version_id": file.CurrentVersionID,
			},
			"error": err.Error(),
		})
		return err
	}

	return nil
}
