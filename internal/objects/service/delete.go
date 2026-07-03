package service

import (
	"context"
	"net/http"
	"os"

	commonErrors "github.com/slodkiadrianek/MINI-BUCKET/common/errors"
)

func (obs *ObjectService) Delete(ctx context.Context, bucketID, userID int, objectKey string, versionID int) error {
	doesBucketExist, err := obs.bucketRepository.Exists(ctx, bucketID)
	if err != nil {
		return err
	}

	if !doesBucketExist {
		return commonErrors.NewAPIError(http.StatusNotFound, "bucket with provided id does not exist")
	}

	isVersioningEnabled, err := obs.bucketRepository.IsVersioningEnabled(ctx, bucketID)
	if err != nil {
		return err
	}

	if isVersioningEnabled {
		return nil
	}
	err = obs.objectRepository.Delete(ctx, objectKey)
	if err != nil {
		return err
	}

  desthPath := "./uploads/" + string(bucketID)  + "/" + objectKey
	err = os.Remove(desthPath)
	if err != nil {
		return err
	}
	return nil
}
