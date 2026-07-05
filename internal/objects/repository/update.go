package repository

import (
	"context"
	"database/sql"

	"github.com/slodkiadrianek/MINI-BUCKET/internal/objects/DTO"
	commonErrors "github.com/slodkiadrianek/MINI-BUCKET/common/errors"
)

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


