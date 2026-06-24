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

func NewObjectRepository(db *sql.DB, loggerService commonInterfaces.Logger) *ObjectRepository {
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
		is_deleted,
		created_at,
		updated_at
	) VALUES ($1,$2,$3,$4,$5,false,NOW(), NOW()) RETURNING id`

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
	err = stmt.QueryRowContext(ctx, file.BucketID, file.ObjectKey, file.ContentType, file.SizeBytes, file.ETag).Scan(&ObjectID)
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

func (or *ObjectRepository) GetObjectKey(ctx context.Context, tx *sql.Tx, objectID int) (bool, string, error) {
	query := "SELECT object_key FROM objects WHERE id = $1 "
	stmt, err := tx.PrepareContext(ctx, query)
	if err != nil {
		or.loggerService.Error(commonErrors.FailedToPrepareQuery, map[string]any{
			"query": query,
			"args": map[string]any{
				"object_id": objectID,
			},
			"error": err.Error(),
		})
		return false, "", err
	}
	var objectKey string
	err = stmt.QueryRowContext(ctx, objectID).Scan(&objectKey)
	if err != nil {
		if errors.Is(err, sql.ErrNoRows) {
			return false, "", nil
		}
		or.loggerService.Error(commonErrors.FailedToExecuteSelectQuery, map[string]any{
			"query": query,
			"args": map[string]any{
				"object_id": objectID,
			},
			"error": err.Error(),
		})
		return false, "", err
	}
	return true, objectKey, nil
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

func (ob *ObjectRepository) GetMetadata(ctx context.Context, bucketID int, objectKey string, versionNumber int) (model.GetMetadata, error) {
	query := `SELECT o.content_type, ov.etag, ov.size_bytes FROM objects o
  INNER JOIN object_versions ov ON o.id = ov.object_id AND ov.version_number = $1
  WHERE o.object_key = $2 AND o.bucket_id = $3
  `
	stmt, err := ob.db.PrepareContext(ctx, query)
	if err != nil {
		ob.loggerService.Error(commonErrors.FailedToPrepareQuery, map[string]any{
			"query": query,
			"args": map[string]any{
				"bucket_id":      bucketID,
				"version_number": versionNumber,
				"object_key":     objectKey,
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

	err = stmt.QueryRowContext(ctx, versionNumber, objectKey, bucketID).Scan(&objectMetadata.ContentType, &objectMetadata.ETAG, &objectMetadata.SizeBytes)
	if err != nil {
		ob.loggerService.Error(commonErrors.FailedToPrepareQuery, map[string]any{
			"query": query,
			"args": map[string]any{
				"bucket_id":      bucketID,
				"version_number": versionNumber,
				"object_key":     objectKey,
			},
			"error": err.Error(),
		})
		return model.GetMetadata{}, err
	}
	return objectMetadata, nil
}

func (or *ObjectRepository) SoftDeleteObject(ctx context.Context, bucketID int, objectKey string) error {
	query := "UPDATE  objects  SET o.is_deleted = true WHERE bucket_id = $1 AND object_key = $2"
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
		return err
	}
	defer func() {
		if closeErr := stmt.Close(); closeErr != nil {
			or.loggerService.Error(commonErrors.FailedToCloseStatement, closeErr)
		}
	}()
	_, err = stmt.ExecContext(ctx, bucketID, objectKey)
	if err != nil {
		or.loggerService.Error(commonErrors.FailedToExecuteUpdateQuery, map[string]any{
			"query": query,
			"args": map[string]any{
				"bucket_id":  bucketID,
				"object_key": objectKey,
			},
			"error": err.Error(),
		})
		return err
	}

	return nil
}

func (or *ObjectRepository) HardDeleteObject(ctx context.Context, bucketID int, objectKey string) error {
	query := "DELETE FROM objects  WHERE bucket_id = $1 AND object_key = $2"
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
		return err
	}
	defer func() {
		if closeErr := stmt.Close(); closeErr != nil {
			or.loggerService.Error(commonErrors.FailedToCloseStatement, closeErr)
		}
	}()
	_, err = stmt.ExecContext(ctx, bucketID, objectKey)
	if err != nil {
		or.loggerService.Error(commonErrors.FailedToExecuteDeleteQuery, map[string]any{
			"query": query,
			"args": map[string]any{
				"bucket_id":  bucketID,
				"object_key": objectKey,
			},
			"error": err.Error(),
		})
		return err
	}

	return nil
}

func (or *ObjectRepository) SoftDeleteVersion(ctx context.Context, bucketID int, objectKey string, versionNumber int) error {
	query := "UPDATE  object_versions ov USING objects o SET ov.is_deleted = true WHERE o.bucket_id = $1 AND o.object_key = $2 AND ov.version_number = $3 AND o.id = ov.object_id"
	stmt, err := or.db.PrepareContext(ctx, query)
	if err != nil {
		or.loggerService.Error(commonErrors.FailedToPrepareQuery, map[string]any{
			"query": query,
			"args": map[string]any{
				"bucket_id":      bucketID,
				"object_key":     objectKey,
				"version_number": versionNumber,
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
	_, err = stmt.ExecContext(ctx, bucketID, objectKey, versionNumber)
	if err != nil {
		or.loggerService.Error(commonErrors.FailedToExecuteUpdateQuery, map[string]any{
			"query": query,
			"args": map[string]any{
				"bucket_id":      bucketID,
				"object_key":     objectKey,
				"version_number": versionNumber,
			},
			"error": err.Error(),
		})
		return err
	}

	return nil
}

func (or *ObjectRepository) HardDeleteVersion(ctx context.Context, bucketID int, objectKey string, versionNumber int) error {
	query := "DELETE FROM object_versions ov USING objects o WHERE o.bucket_id = $1 AND o.object_key = $2 AND ov.version_number = $3 AND o.id = ov.object_id"
	stmt, err := or.db.PrepareContext(ctx, query)
	if err != nil {
		or.loggerService.Error(commonErrors.FailedToPrepareQuery, map[string]any{
			"query": query,
			"args": map[string]any{
				"bucket_id":      bucketID,
				"object_key":     objectKey,
				"version_number": versionNumber,
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
	_, err = stmt.ExecContext(ctx, bucketID, objectKey, versionNumber)
	if err != nil {
		or.loggerService.Error(commonErrors.FailedToExecuteDeleteQuery, map[string]any{
			"query": query,
			"args": map[string]any{
				"bucket_id":      bucketID,
				"object_key":     objectKey,
				"version_number": versionNumber,
			},
			"error": err.Error(),
		})
		return err
	}

	return nil
}
