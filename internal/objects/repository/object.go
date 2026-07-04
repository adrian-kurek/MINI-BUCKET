package repository

import (
	"context"
	"database/sql"
	"errors"

	commonErrors "github.com/slodkiadrianek/MINI-BUCKET/common/errors"
	commonInterfaces "github.com/slodkiadrianek/MINI-BUCKET/common/interfaces"
	DTO "github.com/slodkiadrianek/MINI-BUCKET/internal/objects/DTO"
	"github.com/slodkiadrianek/MINI-BUCKET/internal/objects/model"
)

type ObjectRepository struct {
	db            *sql.DB
	loggerService commonInterfaces.Logger
}

func New(db *sql.DB, loggerService commonInterfaces.Logger) *ObjectRepository {
	return &ObjectRepository{
		db:            db,
		loggerService: loggerService,
	}
}

func (or *ObjectRepository) Create(ctx context.Context, tx *sql.Tx, file DTO.Create) (int, error) {
	query := `INSERT INTO objects (
		bucket_id,
		object_key,
		content_type,
		size_bytes,
		etag,
		storage_class,
    object_uuid,
		created_at,
		updated_at
	) VALUES ($1,$2,$3,$4,$5,$6,$7,NOW(), NOW()) RETURNING id`

	stmt, err := tx.PrepareContext(ctx, query)
	if err != nil {
		or.loggerService.Error(commonErrors.FailedToPrepareQuery, map[string]any{
			"query": query,
			"args": map[string]any{
				"bucket_id":     file.BucketID,
				"object_key":    file.ObjectKey,
				"content_type":  file.ContentType,
				"size_bytes":    file.SizeBytes,
				"etag":          file.ETag,
				"object_uuid":   file.UUID,
				"storage_class": file.StorageClass,
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
	err = stmt.QueryRowContext(
		ctx,
		file.BucketID,
		file.ObjectKey,
		file.ContentType,
		file.SizeBytes,
		file.ETag,
		file.StorageClass,
		file.UUID,
	).Scan(&ObjectID)
	if err != nil {
		or.loggerService.Error(commonErrors.FailedToExecuteInsertQuery, map[string]any{
			"query": query,
			"args": map[string]any{
				"bucket_id":     file.BucketID,
				"object_key":    file.ObjectKey,
				"content_type":  file.ContentType,
				"size_bytes":    file.SizeBytes,
				"etag":          file.ETag,
				"object_uuid":   file.UUID,
				"storage_class": file.StorageClass,
			},
			"error": err.Error(),
		})
		return 0, err
	}

	return ObjectID, nil
}

func (or *ObjectRepository) Update(ctx context.Context, tx *sql.Tx, file DTO.Update) error {
	query := `UPDATE objects SET 
		size_bytes = $1,
		etag = $2,
		storage_class = $3,
    object_uuid = $4,
		updated_at = NOW() WHERE id = $5`

	stmt, err := tx.PrepareContext(ctx, query)
	if err != nil {
		or.loggerService.Error(commonErrors.FailedToPrepareQuery, map[string]any{
			"query": query,
			"args": map[string]any{
				"object_id":     file.ObjectID,
				"size_bytes":    file.SizeBytes,
				"etag":          file.ETag,
				"object_uuid":   file.UUID,
				"storage_class": file.StorageClass,
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

	_, err = stmt.ExecContext(ctx, file.SizeBytes, file.ETag, file.StorageClass, file.UUID, file.ObjectID)
	if err != nil {
		or.loggerService.Error(commonErrors.FailedToExecuteUpdateQuery, map[string]any{
			"query": query,
			"args": map[string]any{
				"object_id":     file.ObjectID,
				"size_bytes":    file.SizeBytes,
				"etag":          file.ETag,
				"object_uuid":   file.UUID,
				"storage_class": file.StorageClass,
			},
			"error": err.Error(),
		})
		return err
	}

	return nil
}

func (or *ObjectRepository) GetObjectID(ctx context.Context, objectKey string, bucketID int) (bool, int, error) {
	query := "SELECT id FROM objects WHERE object_key = $1 AND bucket_id = $2"
	stmt, err := or.db.PrepareContext(ctx, query)
	if err != nil {
		or.loggerService.Error(commonErrors.FailedToPrepareQuery, map[string]any{
			"query": query,
			"args": map[string]any{
				"bucket_id":  bucketID,
				"object_key": objectKey,
			},
			"error": err.Error(),
		})
		return false, 0, err
	}
	var objectID int
	err = stmt.QueryRowContext(ctx, objectKey, bucketID).Scan(&objectID)
	if err != nil {
		if errors.Is(err, sql.ErrNoRows) {
			return false, 0, nil
		}
		or.loggerService.Error(commonErrors.FailedToExecuteSelectQuery, map[string]any{
			"query": query,
			"args": map[string]any{
				"bucket_id":  bucketID,
				"object_key": objectKey,
			},
			"error": err.Error(),
		})
		return false, 0, err
	}
	return true, objectID, nil
}

func (ob *ObjectRepository) UpdateCurrentVersionIDOfObject(ctx context.Context, tx *sql.Tx, objectID int, versionID int) error {
	query := `UPDATE objects SET current_version_id = $1 WHERE id = $2`
	stmt, err := tx.PrepareContext(ctx, query)
	if err != nil {
		ob.loggerService.Error(commonErrors.FailedToPrepareQuery, map[string]any{
			"query": query,
			"args": map[string]any{
				"object_id":          objectID,
				"current_version_id": versionID,
			},
			"error": err.Error(),
		})
		return err
	}
	defer func() {
		if closeErr := stmt.Close(); closeErr != nil {
			ob.loggerService.Error(commonErrors.FailedToCloseStatement, closeErr)
		}
	}()
	_, err = stmt.ExecContext(ctx, versionID, objectID)
	if err != nil {
		ob.loggerService.Error(commonErrors.FailedToExecuteUpdateQuery, map[string]any{
			"query": query,
			"args": map[string]any{
				"object_id":          objectID,
				"current_version_id": versionID,
			},
			"error": err.Error(),
		})
		return err
	}

	return nil
}

func (ob *ObjectRepository) GetMetadata(ctx context.Context, bucketID int, objectKey string) (model.GetMetadata, error) {
	query := `
	SELECT 
		o.content_type,
		o.etag,
		o.size_bytes 
	FROM objects o
  	WHERE o.object_key = $1 AND o.bucket_id = $2`

	stmt, err := ob.db.PrepareContext(ctx, query)
	if err != nil {
		ob.loggerService.Error(commonErrors.FailedToPrepareQuery, map[string]any{
			"query": query,
			"args": map[string]any{
				"bucket_id":  bucketID,
				"object_key": objectKey,
			},
			"error": err.Error(),
		})
		return model.GetMetadata{}, err
	}
	defer func() {
		if closeErr := stmt.Close(); closeErr != nil {
			ob.loggerService.Error(commonErrors.FailedToCloseStatement, closeErr)
		}
	}()

	var objectMetadata model.GetMetadata

	err = stmt.QueryRowContext(ctx, objectKey, bucketID).Scan(
		&objectMetadata.ContentType,
		&objectMetadata.ETAG,
		&objectMetadata.SizeBytes,
	)
	if err != nil {
		ob.loggerService.Error(commonErrors.FailedToPrepareQuery, map[string]any{
			"query": query,
			"args": map[string]any{
				"bucket_id":  bucketID,
				"object_key": objectKey,
			},
			"error": err.Error(),
		})
		return model.GetMetadata{}, err
	}
	return objectMetadata, nil
}


func (or *ObjectRepository) Delete(ctx context.Context, objectKey string) error {
	query := "DELETE FROM objects WHERE object_key = $1"
	stmt, err := or.db.PrepareContext(ctx, query)
	if err != nil {
		or.loggerService.Error(commonErrors.FailedToPrepareQuery, map[string]any{
			"query": query,
			"args": map[string]any{
				"object_key": objectKey,
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
	_, err = stmt.ExecContext(ctx, objectKey)
	if err != nil {
		or.loggerService.Error(commonErrors.FailedToExecuteDeleteQuery, map[string]any{
			"query": query,
			"args": map[string]any{
				"object_key": objectKey,
			},
			"error": err.Error(),
		})
		return err
	}

	return nil
}
