package repository

import (
	"context"
	"database/sql"
	"fmt"
	"strings"

	"github.com/slodkiadrianek/MINI-BUCKET/common/db"
	commonErrors "github.com/slodkiadrianek/MINI-BUCKET/common/errors"
	commonInterfaces "github.com/slodkiadrianek/MINI-BUCKET/common/interfaces"
	"github.com/slodkiadrianek/MINI-BUCKET/internal/objects/model"
	DTO "github.com/slodkiadrianek/MINI-BUCKET/internal/versions/DTO"
)

type VersionRepository struct {
	db            *sql.DB
	loggerService commonInterfaces.Logger
}

func New(db *sql.DB, loggerService commonInterfaces.Logger) *VersionRepository {
	return &VersionRepository{
		db:            db,
		loggerService: loggerService,
	}
}

func (ov *VersionRepository) Create(ctx context.Context, tx *sql.Tx, file DTO.Create) (int, error) {
	query := `INSERT INTO object_versions (
		object_id,
    object_uuid,
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
				"object_id":     file.ObjectID,
				"size_bytes":    file.SizeBytes,
				"etag":          file.ETag,
				"storage_class": file.StorageClass,
				"uuid":          file.UUID,
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
	err = stmt.QueryRowContext(
		ctx,
		file.ObjectID,
		file.UUID,
		file.SizeBytes,
		file.ETag,
		file.StorageClass,
	).Scan(&newVersionID)
	if err != nil {
		ov.loggerService.Error(commonErrors.FailedToExecuteInsertQuery, map[string]any{
			"query": query,
			"args": map[string]any{
				"object_id":     file.ObjectID,
				"size_bytes":    file.SizeBytes,
				"etag":          file.ETag,
				"storage_class": file.StorageClass,
				"uuid":          file.UUID,
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

func (vr *VersionRepository) GetUUIDByID(ctx context.Context, versionID int) (string, error) {
	query := `SELECT object_uuid FROM object_versions WHERE id = $1  `
	stmt, err := vr.db.PrepareContext(ctx, query)
	if err != nil {
		vr.loggerService.Error(commonErrors.FailedToPrepareQuery, map[string]any{
			"query": query,
			"args": map[string]any{
				"version_id": versionID,
			},
			"error": err.Error(),
		})
		return "", err
	}
	defer func() {
		if closeErr := stmt.Close(); closeErr != nil {
			vr.loggerService.Error(commonErrors.FailedToCloseStatement, closeErr)
		}
	}()

	var uuid string
	err = stmt.QueryRowContext(ctx, versionID).Scan(&uuid)
	if err != nil {
		vr.loggerService.Error(commonErrors.FailedToExecuteSelectQuery, map[string]any{
			"query": query,
			"args": map[string]any{
				"version_id": versionID,
			},
			"error": err.Error(),
		})
		return "", err
	}

	return uuid, nil
}

func (vr *VersionRepository) GetUUIDByObjectKey(ctx context.Context, bucketID int, objectKey string) (string, error) {
	query := `SELECT object_uuid FROM object_versions ov 
	INNER JOIN objects o ON o.id = ov.object_id 
	WHERE o.object_key = $1 AND ov.bucket_id = $2  `
	stmt, err := vr.db.PrepareContext(ctx, query)
	if err != nil {
		vr.loggerService.Error(commonErrors.FailedToPrepareQuery, map[string]any{
			"query": query,
			"args": map[string]any{
				"bucket_id":  bucketID,
				"object_key": objectKey,
			},
			"error": err.Error(),
		})
		return "", err
	}
	defer func() {
		if closeErr := stmt.Close(); closeErr != nil {
			vr.loggerService.Error(commonErrors.FailedToCloseStatement, closeErr)
		}
	}()

	var uuid string
	err = stmt.QueryRowContext(ctx, objectKey, bucketID).Scan(&uuid)
	if err != nil {
		vr.loggerService.Error(commonErrors.FailedToExecuteSelectQuery, map[string]any{
			"query": query,
			"args": map[string]any{
				"bucket_id":  bucketID,
				"object_key": objectKey,
			},
			"error": err.Error(),
		})
		return "", err
	}

	return uuid, nil
}

func (vr *VersionRepository) GetMetadata(ctx context.Context, bucketID int, objectKey string, versionID int) (model.GetMetadata, error) {
	query := `
	SELECT 
		ov.size_bytes,
		ov.etag,
		ov.content_type,
		ov.is_deleted
	FROM object_versions ov
	INNER JOIN objects o ON ov.object_id = o.id
	WHERE o.bucket_id = $1
		  AND o.object_key = $2
		  AND (
		        ($3 > 0 AND ov.version_id = $3)
		     OR ($3 <= 0 AND ov.id = o.current_version_id)
		      )
	`
	stmt, err := vr.db.PrepareContext(ctx, query)
	if err != nil {
		vr.loggerService.Error(commonErrors.FailedToPrepareQuery, map[string]any{
			"query": query,
			"args": map[string]any{
				"object_key": objectKey,
				"bucket_id":  bucketID,
				"version_id": versionID,
			},
			"error": err.Error(),
		})
		return model.GetMetadata{}, err
	}
	defer func() {
		if closeErr := stmt.Close(); closeErr != nil {
			vr.loggerService.Error(commonErrors.FailedToCloseStatement, closeErr)
		}
	}()

	var metadata model.GetMetadata
	err = stmt.QueryRowContext(
		ctx,
		bucketID,
		objectKey,
		versionID,
	).Scan(&metadata.SizeBytes, &metadata.ETAG, &metadata.ContentType, &metadata.IsDeleted)
	if err != nil {
		vr.loggerService.Error(commonErrors.FailedToExecuteSelectQuery, map[string]any{
			"query": query,
			"args": map[string]any{
				"object_key": objectKey,
				"bucket_id":  bucketID,
				"version_id": versionID,
			},
			"error": err.Error(),
		})
		return model.GetMetadata{}, err
	}

	return metadata, nil
}

func (vr *VersionRepository) Delete(ctx context.Context, versionID int) error {
	query := "DELETE FROM object_versions WHERE id = $1"
	stmt, err := vr.db.PrepareContext(ctx, query)
	if err != nil {
		vr.loggerService.Error(commonErrors.FailedToPrepareQuery, map[string]any{
			"query": query,
			"args": map[string]any{
				"version_id": versionID,
			},
			"error": err.Error(),
		})
		return err
	}
	defer func() {
		if closeErr := stmt.Close(); closeErr != nil {
			vr.loggerService.Error(commonErrors.FailedToCloseStatement, closeErr)
		}
	}()

	_, err = stmt.ExecContext(ctx, versionID)
	if err != nil {
		vr.loggerService.Error(commonErrors.FailedToExecuteSelectQuery, map[string]any{
			"query": query,
			"args": map[string]any{
				"version_id": versionID,
			},
			"error": err.Error(),
		})
		return err
	}

	return nil
}

func (vr *VersionRepository) CreateDeleteMarker(ctx context.Context, tx *sql.Tx, objectID int) (int, error) {
	query := `INSERT INTO object_versions(
		object_id,
    object_uuid,
		is_deleted,
		size_bytes,
		etag,
		storage_class,
		created_at,
		updated_at
	) VALUES($1,'',TRUE, 0,'','STANDARD',NOW(),NOW()) RETURNING id`

	stmt, err := tx.PrepareContext(ctx, query)
	if err != nil {
		vr.loggerService.Error(commonErrors.FailedToPrepareQuery, map[string]any{
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
			vr.loggerService.Error(commonErrors.FailedToCloseStatement, closeErr)
		}
	}()

	var newVersionID int
	err = stmt.QueryRowContext(
		ctx,
		objectID,
	).Scan(&newVersionID)
	if err != nil {
		vr.loggerService.Error(commonErrors.FailedToExecuteInsertQuery, map[string]any{
			"query": query,
			"args": map[string]any{
				"object_id": objectID,
			},
			"error": err.Error(),
		})
		return 0, err
	}

	return newVersionID, nil
}

func (vr *VersionRepository) CreateManyDeleteMarkers(ctx context.Context, tx *sql.Tx, objectIDs []int) ([]int, error) {
	placeholders := make([]string, len(objectIDs))
	args := make([]any, len(objectIDs))
	for i := 0; i < len(objectIDs); i++ {
		placeholders[i] = fmt.Sprintf("($%d,'',TRUE, 0,'','STANDARD',NOW(),NOW())", i+1)
		args[i] = objectIDs[i]
	}
	query := fmt.Sprintf(`INSERT INTO object_versions(
		object_id,
    object_uuid,
		is_deleted,
		size_bytes,
		etag,
		storage_class,
		created_at,
		updated_at
	) VALUES %s RETURNING id`, strings.Join(placeholders, ","))

	stmt, err := tx.PrepareContext(ctx, query)
	if err != nil {
		vr.loggerService.Error(commonErrors.FailedToPrepareQuery, map[string]any{
			"query": query,
			"args": map[string]any{
				"object_ids": objectIDs,
			},
			"error": err.Error(),
		})
		return nil, err
	}
	defer func() {
		if closeErr := stmt.Close(); closeErr != nil {
			vr.loggerService.Error(commonErrors.FailedToCloseStatement, closeErr)
		}
	}()

	rows, err := stmt.QueryContext(
		ctx,
		args...,
	)
	if err != nil {
		vr.loggerService.Error(commonErrors.FailedToExecuteInsertQuery, map[string]any{
			"query": query,
			"args": map[string]any{
				"object_ids": objectIDs,
			},
			"error": err.Error(),
		})
		return nil, err
	}
	defer func() {
		if closeErr := rows.Close(); closeErr != nil {
			vr.loggerService.Error(commonErrors.FailedToCloseStatement, map[string]any{
				"query": query,
				"args": map[string]any{
					"object_ids": objectIDs,
				},
				"error": err.Error(),
			})
		}
	}()

	versionIDs := make([]int, 0, len(objectIDs))
	found := false
	for rows.Next() {
		found = true
		err = db.ReadRow(rows, &versionIDs)
		if err != nil {
			vr.loggerService.Error(commonErrors.FailedToScanRow, map[string]any{
				"query": query,
				"args": map[string]any{
					"object_ids": objectIDs,
				},
				"error": err.Error(),
			})
			return nil, err
		}
	}
	if err = rows.Err(); err != nil {
		vr.loggerService.Error(commonErrors.FailedToScanRows, map[string]any{
			"query": query,
			"args": map[string]any{
				"object_ids": objectIDs,
			},
			"error": err.Error(),
		})
		return nil, err
	}
	if !found {
		return nil, commonErrors.NotFound("")
	}

	return versionIDs, nil
}

func (vr *VersionRepository) GetUUIDsAndObjectKeysByIDs(
	ctx context.Context,
	bucketID int,
	versionIDs []int,
) ([]model.ObjectKeyWithUUID, error) {
	placeholders := db.CreatePlaceholders(len(versionIDs))
	query := fmt.Sprintf(`SELECT o.object_key, o.object_uuid FROM object_versions ov INNER JOIN objects o ON o.id = ov.object_id
	WHERE ov.id IN ( %s ) AND o.bucket_id = $%d`, placeholders, len(versionIDs)+1)
	args := db.CreateArgs(versionIDs, len(versionIDs)+1)
	args = append(args, bucketID)

	stmt, err := vr.db.PrepareContext(ctx, query)
	if err != nil {
		vr.loggerService.Error(commonErrors.FailedToPrepareQuery, map[string]any{
			"query": query,
			"args": map[string]any{
				"bucket_id":   bucketID,
				"version_ids": versionIDs,
			},
			"error": err.Error(),
		})
		return nil, err
	}
	defer func() {
		if closeErr := stmt.Close(); closeErr != nil {
			vr.loggerService.Error(commonErrors.FailedToCloseStatement, closeErr)
		}
	}()

	rows, err := stmt.QueryContext(ctx, args...)
	if err != nil {
		vr.loggerService.Error(commonErrors.FailedToExecuteSelectQuery, map[string]any{
			"query": query,
			"args": map[string]any{
				"bucket_id":   bucketID,
				"version_ids": versionIDs,
			},
			"error": err.Error(),
		})
		return nil, err
	}
	defer func() {
		if closeErr := rows.Close(); closeErr != nil {
			vr.loggerService.Error(commonErrors.FailedToCloseStatement, closeErr)
		}
	}()

	objectKeysWithUUIDs := make([]model.ObjectKeyWithUUID, 0, len(versionIDs))
	found := false
	for rows.Next() {
		found = true
		var objectKeyWithUUID model.ObjectKeyWithUUID
		err = rows.Scan(&objectKeyWithUUID.ObjectKey, &objectKeyWithUUID.ObjectUUID)
		if err != nil {
			vr.loggerService.Error(commonErrors.FailedToScanRow, map[string]any{
				"query": query,
				"args": map[string]any{
					"bucket_id":   bucketID,
					"version_ids": versionIDs,
				},
				"error": err.Error(),
			})
			return nil, err
		}
		objectKeysWithUUIDs = append(objectKeysWithUUIDs, objectKeyWithUUID)
	}
	if err = rows.Err(); err != nil {
		vr.loggerService.Error(commonErrors.FailedToScanRows, map[string]any{
			"query": query,
			"args": map[string]any{
				"bucket_id":   bucketID,
				"version_ids": versionIDs,
			},
			"error": err.Error(),
		})
		return nil, err
	}
	if !found {
		return nil, commonErrors.NotFound("")
	}

	return objectKeysWithUUIDs, nil
}

func (vr *VersionRepository) GetUUIDsAndObjectKeysByObjectKeys(ctx context.Context, bucketID int, objectKeys []string) ([]model.ObjectKeyWithUUID, error) {
	placeholders := db.CreatePlaceholders(len(objectKeys))
	query := fmt.Sprintf(`SELECT o.object_key,o.object_uuid FROM object_versions ov 
	INNER JOIN objects o ON o.id = ov.object_id 
	WHERE o.object_key IN ( %s)  AND o.bucket_id = $%d`, placeholders, len(objectKeys)+1)
	args := db.CreateArgs(objectKeys, len(objectKeys)+1)
	args = append(args, bucketID)

	stmt, err := vr.db.PrepareContext(ctx, query)
	if err != nil {
		vr.loggerService.Error(commonErrors.FailedToPrepareQuery, map[string]any{
			"query": query,
			"args": map[string]any{
				"bucket_id":   bucketID,
				"object_keys": objectKeys,
			},
			"error": err.Error(),
		})
		return nil, err
	}
	defer func() {
		if closeErr := stmt.Close(); closeErr != nil {
			vr.loggerService.Error(commonErrors.FailedToCloseStatement, closeErr)
		}
	}()

	rows, err := stmt.QueryContext(ctx, args...)
	if err != nil {
		vr.loggerService.Error(commonErrors.FailedToExecuteSelectQuery, map[string]any{
			"query": query,
			"args": map[string]any{
				"bucket_id":   bucketID,
				"object_keys": objectKeys,
			},
			"error": err.Error(),
		})
		return nil, err
	}
	defer func() {
		if closeErr := rows.Close(); closeErr != nil {
			vr.loggerService.Error(commonErrors.FailedToCloseStatement, closeErr)
		}
	}()

	objectKeysWithUUIDs := make([]model.ObjectKeyWithUUID, 0, len(objectKeys))
	found := false
	for rows.Next() {
		found = true
		var objectKeyWithUUID model.ObjectKeyWithUUID
		err = rows.Scan(&objectKeyWithUUID.ObjectKey, &objectKeyWithUUID.ObjectUUID)
		if err != nil {
			vr.loggerService.Error(commonErrors.FailedToScanRow, map[string]any{
				"query": query,
				"args": map[string]any{
					"bucket_id":   bucketID,
					"object_keys": objectKeys,
				},
				"error": err.Error(),
			})
			return nil, err
		}
	}
	if err = rows.Err(); err != nil {
		vr.loggerService.Error(commonErrors.FailedToScanRows, map[string]any{
			"query": query,
			"args": map[string]any{
				"bucket_id":   bucketID,
				"object_keys": objectKeys,
			},
			"error": err.Error(),
		})
		return nil, err
	}
	if !found {
		return nil, commonErrors.NotFound("")
	}

	return objectKeysWithUUIDs, nil
}

func (vr *VersionRepository) DeleteMany(ctx context.Context, versionIDs []int, bucketID int) error {
	placeholders := db.CreatePlaceholders(len(versionIDs))
	query := fmt.Sprintf("DELETE FROM object_versions ov INNER JOIN objects o ON o.id = ov.object_id  WHERE ov.id IN ( %s ) AND o.bucket_id = $%d", placeholders, len(versionIDs)+1)
	stmt, err := vr.db.PrepareContext(ctx, query)
	args := db.CreateArgs(versionIDs, len(versionIDs)+1)
	args = append(args, bucketID)

	if err != nil {
		vr.loggerService.Error(commonErrors.FailedToPrepareQuery, map[string]any{
			"query": query,
			"args": map[string]any{
				"version_ids": versionIDs,
				"bucket_id":   bucketID,
			},
			"error": err.Error(),
		})
		return err
	}
	defer func() {
		if closeErr := stmt.Close(); closeErr != nil {
			vr.loggerService.Error(commonErrors.FailedToCloseStatement, closeErr)
		}
	}()

	_, err = stmt.ExecContext(ctx, args...)
	if err != nil {
		vr.loggerService.Error(commonErrors.FailedToExecuteSelectQuery, map[string]any{
			"query": query,
			"args": map[string]any{
				"version_ids": versionIDs,
				"bucket_id":   bucketID,
			},
			"error": err.Error(),
		})
		return err
	}

	return nil
}
