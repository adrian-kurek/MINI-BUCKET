package service

import (
	"context"
	"net/http"
	"os"
	"strconv"

	commonErrors "github.com/slodkiadrianek/MINI-BUCKET/common/errors"
)

func (obs *ObjectService) CheckExecutePermissions(ctx context.Context, bucketID, userID int) error {

	permission, err := obs.permissionRepository.GetPermissionValByUserID(ctx, bucketID, userID)
	if err != nil {
		return err
	}
	if permission != 2 && permission != 6 && permission != 3 && permission != 7 {
		obs.loggerService.Info("user tried to perform operation which is not allowed for him", userID)
		return commonErrors.NewAPIError(http.StatusForbidden, "you are not allowed to do this action")
	}
	return nil
}

func (obs *ObjectService) CreateDeleteMarker(ctx context.Context, objectKey string, bucketID int) error {

	doesObjectExist, objectID, err := obs.objectRepository.GetObjectID(ctx, objectKey, bucketID)
	if !doesObjectExist {
		return commonErrors.NewAPIError(http.StatusNotFound, "failed to find object with provided id")
	}
	if err != nil {
		return err
	}

	tx, err := obs.db.BeginTx(ctx, nil)
	if err != nil {
		return err
	}

	deleteMarkerID, err := obs.versionRepository.CreateDeleteMarker(ctx, tx, objectID)
	if err != nil {
		tx.Rollback()
		return err
	}

	err = obs.objectRepository.UpdateCurrentVersionIDOfObject(ctx, tx, objectID, deleteMarkerID)
	if err != nil {
		tx.Rollback()
		return err
	}

	err = tx.Commit()
	if err != nil {
		return err
	}

	return nil
}

func (obs *ObjectService) DeleteObjectVersionByID(ctx context.Context, objectKey string, bucketID, versionID int) error {
	objectUUID, err := obs.versionRepository.GetUUIDByID(ctx, versionID)
	if err != nil {
		return err
	}

	err = obs.versionRepository.Delete(ctx, versionID)
	if err != nil {
		return err
	}

	destPath := "./uploads/" + strconv.Itoa(bucketID) + "/" + objectKey + "-" + objectUUID
	err = os.Remove(destPath)
	if err != nil {
		return err
	}

	return nil
}

func (obs *ObjectService) DeleteObject(ctx context.Context, objectKey string, bucketID int) error {
	objectUUID, err := obs.objectRepository.GetUUIDByID(ctx, objectKey, bucketID)
	if err != nil {
		return err
	}

	err = obs.objectRepository.Delete(ctx, objectKey)
	if err != nil {
		return err
	}

	desthPath := "./uploads/" + strconv.Itoa(bucketID) + "/" + objectKey + "-" + objectUUID
	err = os.Remove(desthPath)
	if err != nil {
		return err
	}

	return nil
}

func (obs *ObjectService) Delete(ctx context.Context, bucketID, userID int, objectKey string, versionID int) error {
	err := obs.CheckExecutePermissions(ctx, bucketID, userID)
	if err != nil {
		return err
	}

	err = obs.CheckDoesBucketExist(ctx, bucketID)
	if err != nil {
		return err
	}

	isVersioningEnabled, err := obs.bucketRepository.IsVersioningEnabled(ctx, bucketID)
	if err != nil {
		return err
	}

	if isVersioningEnabled {
		if versionID == 0 {
			return obs.CreateDeleteMarker(ctx, objectKey, bucketID)
		}
		return obs.DeleteObjectVersionByID(ctx, objectKey, bucketID, versionID)
	}
	return obs.DeleteObject(ctx, objectKey, bucketID)
}
