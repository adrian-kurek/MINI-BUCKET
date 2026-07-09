package repository

import (
	"context"
	"database/sql"

	"github.com/slodkiadrianek/MINI-BUCKET/internal/objects/DTO"
	commonErrors "github.com/slodkiadrianek/MINI-BUCKET/common/errors"
)

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

