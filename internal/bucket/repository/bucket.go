package repository

import (
	"context"
	"database/sql"
	"errors"

	commonErrors "github.com/slodkiadrianek/MINI-BUCKET/common/errors"
	commonInterfaces "github.com/slodkiadrianek/MINI-BUCKET/common/interfaces"
	bucketDTO "github.com/slodkiadrianek/MINI-BUCKET/internal/bucket/DTO"
)

type BucketRepository struct {
	loggerService commonInterfaces.Logger
	db            *sql.DB
}

func NewBucketRepository(loggerService commonInterfaces.Logger, db *sql.DB) *BucketRepository {
	return &BucketRepository{
		loggerService: loggerService,
		db:            db,
	}
}

func (br *BucketRepository) Create(ctx context.Context, userID int, bucket bucketDTO.BucketInput) (int, error) {
	query := `INSERT INTO buckets (name,user_id,region,versioning_enabled,public_access,storage_class,encryption_enabled, created_at,updated_at) VALUES ($1, $2, $3, $4, $5, $6,$7, NOW(), NOW())`

	stmt, err := br.db.PrepareContext(ctx, query)
	if err != nil {
		br.loggerService.Error(commonErrors.FailedToPrepareQuery, map[string]any{
			"query": query,
			"args": map[string]any{
				"name":               bucket.Name,
				"user_id":            userID,
				"region":             "",
				"versioning_enabled": bucket.VersioningEnabled,
				"public_access":      bucket.PublicAccess,
				"storage_class":      bucket.StorageClass,
				"encryption_enabled": bucket.EncryptionEnabled,
			},
			"error": err.Error(),
		})
		return 0, err
	}
	defer func() {
		if closeErr := stmt.Close(); closeErr != nil {
			br.loggerService.Error(commonErrors.FailedToCloseStatement, closeErr)
		}
	}()

	var bucketID int
	err = stmt.QueryRowContext(ctx, bucket.Name, userID, "", bucket.VersioningEnabled, bucket.PublicAccess, bucket.StorageClass, bucket.EncryptionEnabled).Scan(&bucketID)
	if err != nil {
		br.loggerService.Error(commonErrors.FailedToExecuteInsertQuery, map[string]any{
			"query": query,
			"args": map[string]any{
				"name":               bucket.Name,
				"user_id":            userID,
				"region":             "",
				"versioning_enabled": bucket.VersioningEnabled,
				"public_access":      bucket.PublicAccess,
				"storage_class":      bucket.StorageClass,
				"encryption_enabled": bucket.EncryptionEnabled,
			},
			"error": err.Error(),
		})
		return 0, err
	}

	return bucketID, nil
}

func (br *BucketRepository) Update(ctx context.Context, bucketID, userID int, bucket bucketDTO.BucketInput) error {
	query := "UPDATE buckets SET name = $1,versioning_enabled = $2, public_access = $3, storage_class = $4, encryption_enabled = $5, updated_at = NOW() WHERE id = $6 AND owner_id = $7"

	stmt, err := br.db.PrepareContext(ctx, query)
	if err != nil {
		br.loggerService.Error(commonErrors.FailedToPrepareQuery, map[string]any{
			"query": query,
			"args": map[string]any{
				"name":               bucket.Name,
				"user_id":            userID,
				"region":             "",
				"versioning_enabled": bucket.VersioningEnabled,
				"public_access":      bucket.PublicAccess,
				"storage_class":      bucket.StorageClass,
				"encryption_enabled": bucket.EncryptionEnabled,
			},
			"error": err.Error(),
		})
		return err
	}
	defer func() {
		if closeErr := stmt.Close(); closeErr != nil {
			br.loggerService.Error(commonErrors.FailedToCloseStatement, closeErr)
		}
	}()

	_, err = stmt.ExecContext(ctx, bucket.Name, bucket.VersioningEnabled, bucket.PublicAccess, bucket.StorageClass, bucket.EncryptionEnabled, bucketID, userID)
	if err != nil {
		br.loggerService.Error(commonErrors.FailedToExecuteInsertQuery, map[string]any{
			"query": query,
			"args": map[string]any{
				"name":               bucket.Name,
				"user_id":            userID,
				"region":             "",
				"versioning_enabled": bucket.VersioningEnabled,
				"public_access":      bucket.PublicAccess,
				"storage_class":      bucket.StorageClass,
				"encryption_enabled": bucket.EncryptionEnabled,
			},
			"error": err.Error(),
		})
		return err
	}
	return nil
}

func (br *BucketRepository) Exists(ctx context.Context, bucketID int) (bool, error) {
	query := "SELECT id FROM buckets WHERE id = $1"
	stmt, err := br.db.PrepareContext(ctx, query)
	if err != nil {
		br.loggerService.Error(commonErrors.FailedToPrepareQuery, map[string]any{
			"query": query,
			"args": map[string]any{
				"bucket_id": bucketID,
			},
			"error": err.Error(),
		})
		return false, err
	}

	_, err = stmt.QueryContext(ctx, bucketID)
	if err != nil {
		if errors.Is(err, sql.ErrNoRows) {
			return false, nil
		}
		br.loggerService.Error(commonErrors.FailedToExecuteSelectQuery, map[string]any{
			"query": query,
			"args": map[string]any{
				"bucket_id": bucketID,
			},
			"error": err.Error(),
		})
		return false, err
	}
	return true, nil
}
