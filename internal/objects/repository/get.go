package repository

import (
	"context"
	"database/sql"
	"errors"
	"net/http"

	commonErrors "github.com/slodkiadrianek/MINI-BUCKET/common/errors"
	"github.com/slodkiadrianek/MINI-BUCKET/internal/objects/model"
)

func (or *ObjectRepository) GetObjectID(ctx context.Context, objectKey string, bucketID int) (bool,int, error) {
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
		return  false,0, err
	}
	var objectID int
	err = stmt.QueryRowContext(ctx, objectKey, bucketID).Scan(&objectID)
	if err != nil {
		if errors.Is(err,sql.ErrNoRows){
			return false,0,nil
		}

		or.loggerService.Error(commonErrors.FailedToExecuteSelectQuery, map[string]any{
			"query": query,
			"args": map[string]any{
				"bucket_id":  bucketID,
				"object_key": objectKey,
			},
			"error": err.Error(),
		})
		return  false,0, err
	}
	return  true,objectID, nil
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
		if errors.Is(err,sql.ErrNoRows){
			return model.GetMetadata{},commonErrors.NewAPIError(http.StatusNotFound,"failed to find object with provided objectKey and bucketID")
		}

		ob.loggerService.Error(commonErrors.FailedToExecuteSelectQuery, map[string]any{
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

func (or *ObjectRepository) GetUUIDByID(ctx context.Context,  objectKey string, bucketID int) (string, error) {
	query := `SELECT object_uuid FROM objects WHERE object_key = $1 AND bucket_id = $2 `
	stmt, err := or.db.PrepareContext(ctx, query)
	if err != nil {
		or.loggerService.Error(commonErrors.FailedToPrepareQuery, map[string]any{
			"query": query,
			"args": map[string]any{
				"object_key": objectKey,
				"bucket_id": bucketID,
			},
			"error": err.Error(),
		})
		return "", err
	}
	defer func() {
		if closeErr := stmt.Close(); closeErr != nil {
			or.loggerService.Error(commonErrors.FailedToCloseStatement, closeErr)
		}
	}()

	var uuid string 
	err = stmt.QueryRowContext(ctx, objectKey,bucketID).Scan(&uuid)
	if err != nil {
		if errors.Is(err,sql.ErrNoRows){
			return "",commonErrors.NewAPIError(http.StatusNotFound,"failed to find object with provided objectKey and bucketID")
		}

		or.loggerService.Error(commonErrors.FailedToExecuteSelectQuery, map[string]any{
			"query": query,
			"args": map[string]any{
				"object_key": objectKey,
				"bucket_id": bucketID,
			},
			"error": err.Error(),
		})
		return "", err
	}

	return uuid, nil
}
