package service

import (
	"context"
	"net/http"
	"strconv"

	commonErrors "github.com/slodkiadrianek/MINI-BUCKET/common/errors"
	"github.com/slodkiadrianek/MINI-BUCKET/internal/objects/model"
)

func (obs *ObjectService) CheckIsVersionDeleted(isDeleted bool, versionID int) error {
	if isDeleted {
		if versionID > 0 {
			return commonErrors.NewAPIError(http.StatusMethodNotAllowed, "")
		}

		return commonErrors.NewAPIError(http.StatusNotFound, "")
	}
	return nil
}

func (obs *ObjectService) GetWithVersioningEnabled(ctx context.Context, objectKey string, bucketID, versionID int) (model.GetMetadata, string, error) {
	metadata, err := obs.versionRepository.GetMetadata(ctx, bucketID, objectKey, versionID)
	if err != nil {
		return model.GetMetadata{}, "", err
	}

	err = obs.CheckIsVersionDeleted(metadata.IsDeleted, versionID)
	if err != nil {
		return model.GetMetadata{}, "", err
	}

	objectUUID, err := obs.versionRepository.GetUUIDByObjectKey(ctx, bucketID, objectKey)
	if err != nil {
		return model.GetMetadata{}, "", err
	}

	destPath := "./uploads/" + strconv.Itoa(bucketID) + "/" + objectKey + "-" + objectUUID

	return metadata, destPath, nil
}

func (obs *ObjectService) GetWithVersioningDisabled(
	ctx context.Context,
	objectKey string,
	bucketID int,
) (model.GetMetadata, string, error) {
	objectUUID, err := obs.objectRepository.GetUUIDByID(ctx, objectKey, bucketID)
	if err != nil {
		return model.GetMetadata{}, "", err
	}

	metadata, err := obs.objectRepository.GetMetadata(ctx, bucketID, objectKey)
	if err != nil {
		return model.GetMetadata{}, "", err
	}

	destPath := "./uploads/" + strconv.Itoa(bucketID) + "/" + objectKey + "-" + objectUUID

	return metadata, destPath, nil
}

func (obs *ObjectService) Get(
	ctx context.Context,
	bucketID int,
	versionID int,
	objectKey string,
) (model.GetMetadata, string, error) {
	isVersioningEnabled, err := obs.bucketRepository.IsVersioningEnabled(ctx, bucketID)
	if err != nil {
		return model.GetMetadata{}, "", err
	}
	if isVersioningEnabled {
		return obs.GetWithVersioningEnabled(ctx, objectKey, bucketID, versionID)
	}

	return obs.GetWithVersioningDisabled(ctx, objectKey, bucketID)
}
