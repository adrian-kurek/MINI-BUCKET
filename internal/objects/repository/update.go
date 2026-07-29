package repository

import (
	"context"
	"database/sql"
	"fmt"
	"strings"

	commonErrors "github.com/slodkiadrianek/MINI-BUCKET/common/errors"
	"github.com/slodkiadrianek/MINI-BUCKET/internal/objects/DTO"
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

func (ob *ObjectRepository) UpdateCurrentVersionIDsOfObjects(
	ctx context.Context,
	tx *sql.Tx,
	objectIDs []int,
	versionIDs []int,
) error {
	placeholders := make([]string, 0, len(versionIDs))
	args := make([]any, 0, len(versionIDs))
	argPos := 1
	for i, objectID := range objectIDs {
		preparedValues := fmt.Sprintf("($%d,$%d)", argPos, argPos+1)
		placeholders = append(placeholders, preparedValues)
		args = append(args, objectID, versionIDs[i])
		argPos += 2
	}
	query := fmt.Sprintf(`UPDATE objects o 
	SET current_version_id = d.current_version_id 
	from (values %s ) as d(object_id, current_version_id) 
	WHERE o.id = d.object_id`, strings.Join(placeholders, ","))
	stmt, err := tx.PrepareContext(ctx, query)
	if err != nil {
		ob.loggerService.Error(commonErrors.FailedToPrepareQuery, map[string]any{
			"query": query,
			"args": map[string]any{
				"object_ids": objectIDs,
				"verion_ids": versionIDs,
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

	_, err = stmt.ExecContext(ctx, args...)
	if err != nil {
		ob.loggerService.Error(commonErrors.FailedToExecuteUpdateQuery, map[string]any{
			"query": query,
			"args": map[string]any{
				"object_ids": objectIDs,
				"verion_ids": versionIDs,
			},
			"error": err.Error(),
		})
		return err
	}

	return nil
}
