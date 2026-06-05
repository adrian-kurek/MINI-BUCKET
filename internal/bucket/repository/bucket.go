package repository

import (
	"context"
	"database/sql"
	"time"

	bucketDTO "github.com/slodkiadrianek/MINI-BUCKET/internal/bucket/DTO"
	commonErrors "github.com/slodkiadrianek/MINI-BUCKET/internal/common/errors"
	commonInterfaces "github.com/slodkiadrianek/MINI-BUCKET/internal/common/interfaces"
)

type BucketRepository struct {
	logger commonInterfaces.Logger
	db     *sql.DB
}

func NewBucketRepository(logger commonInterfaces.Logger, db *sql.DB) *BucketRepository {
	return &BucketRepository{
		logger: logger,
		db:     db,
	}
}

func (br *BucketRepository) Create(ctx context.Context, userID int, bucket bucketDTO.BucketInput) error {
	query := `INSERT INTO buckets (name,user_id,region,versioning_enabled,public_access,storage_class,encryption_enabled, created_at,updated_at) VALUES ($1, $2, $3, $4, $5, $6,$7, NOW(), NOW())`

	stmt, err := br.db.PrepareContext(ctx, query)
	if err != nil {
		br.logger.Error(commonErrors.FailedToPrepareQuery, map[string]any{
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
	}
	defer func() {
		if closeErr := stmt.Close(); closeErr != nil {
			br.logger.Error(commonErrors.FailedToCloseStatement, closeErr)
		}
	}()

	_, err = stmt.ExecContext(ctx, bucket.Name, userID, "", bucket.VersioningEnabled, bucket.PublicAccess, bucket.StorageClass, bucket.EncryptionEnabled, time.Now(), time.Now())
	if err != nil {
		br.logger.Error(commonErrors.FailedToExecuteInsertQuery, map[string]any{
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
