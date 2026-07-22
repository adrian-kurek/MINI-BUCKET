package service

import (
	"context"
	"errors"
	"net/http"
	"os"
	"strconv"
	"sync"

	commonErrors "github.com/slodkiadrianek/MINI-BUCKET/common/errors"
	"github.com/slodkiadrianek/MINI-BUCKET/internal/objects/DTO"
	"github.com/slodkiadrianek/MINI-BUCKET/internal/objects/model"
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

	err = obs.objectRepository.DeleteOne(ctx, objectKey)
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

func (obs *ObjectService) DeleteManyFiles(bucketID int, objectKeysWithUUIDs []model.ObjectKeyWithUUID) error {
	errs := make([]error, 0, len(objectKeysWithUUIDs))
	var mu sync.Mutex
	wg := sync.WaitGroup{}
	ch := make(chan model.ObjectKeyWithUUID, len(objectKeysWithUUIDs))

	wg.Add(len(objectKeysWithUUIDs))
	for i := 0; i < len(objectKeysWithUUIDs); i++ {
		go func() {
			defer wg.Done()
			for objectKeyWithUUID := range ch {
				desthPath := "./uploads/" + strconv.Itoa(bucketID) + "/" + objectKeyWithUUID.ObjectKey + "-" + objectKeyWithUUID.ObjectUUID
				err := os.Remove(desthPath)
				if err != nil {
					mu.Lock()
					errs = append(errs, err)
					mu.Unlock()
				}
			}
		}()
	}

	for _, item := range objectKeysWithUUIDs {
		ch <- item
	}
	close(ch)

	wg.Wait()

	if len(errs) > 0 {
		obs.loggerService.Error("failed to delete files", errs)
		return errors.Join(errs...)
	}

	return nil
}

func (obs *ObjectService) DeleteManyObjects(ctx context.Context, bucketID int, objectKeys []string) error {
	objectKeysWithUUIDs, err := obs.versionRepository.GetUUIDsAndObjectKeysByObjectKeys(ctx, bucketID, objectKeys)
	if err != nil {
		return err
	}
	objectKeysFromDB := make([]string, len(objectKeysWithUUIDs))
	for i := 0; i < len(objectKeysWithUUIDs); i++ {
		objectKeysFromDB[i] = objectKeysWithUUIDs[i].ObjectKey
	}

	err = obs.objectRepository.DeleteMany(ctx, objectKeysFromDB)
	if err != nil {
		return err
	}
	return nil
}

func (obs *ObjectService) isAvailableForDeletion(ctx context.Context, bucketID, userID int) error {
	err := obs.CheckExecutePermissions(ctx, bucketID, userID)
	if err != nil {
		return err
	}

	err = obs.CheckDoesBucketExist(ctx, bucketID)
	if err != nil {
		return err
	}
	return nil
}

func (obs *ObjectService) Delete(ctx context.Context, bucketID, userID int, objectKey string, versionID int) error {
	err := obs.isAvailableForDeletion(ctx, bucketID, userID)
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

func (obs *ObjectService) DeleteMany(ctx context.Context, bucketID, userID int, filesToDelete DTO.DeleteManyFiles) error {
	err := obs.isAvailableForDeletion(ctx, bucketID, userID)
	if err != nil {
		return err
	}

	isVersioningEnabled, err := obs.bucketRepository.IsVersioningEnabled(ctx, bucketID)
	if err != nil {
		return err
	}
}
