package service

import "context"

// import (
//
//	"context"
//	"os"
//
//	commonErrors "github.com/slodkiadrianek/MINI-BUCKET/common/errors"
//
// )
//
//	func (obs *ObjectService) checkExecutePermissions(ctx context.Context, bucketID, userID int) error {
//		permission, err := obs.permissionRepository.GetPermissionValByUserID(ctx, bucketID, userID)
//		if err != nil {
//			return err
//		}
//		if permission != 1 && permission != 3 && permission != 5 && permission != 7 {
//			obs.loggerService.Info("user tried to perform operation which is not allowed for him", userID)
//			return commonErrors.NewAPIError(403, "you are not allowed to do this action")
//		}
//		return nil
//	}
//
//	func (obs *ObjectService) hardDeleteObject(ctx context.Context, bucketID int, objectKey string, versionNumber int) error {
//		err := obs.objectRepository.HardDeleteVersion(ctx, bucketID, objectKey, versionNumber)
//		removePath, err := obs.createDestPath(bucketID, versionNumber, objectKey)
//		if err != nil {
//			return err
//		}
//		return os.Remove(removePath)
//	}
//
//	func (obs *ObjectService) hardDeleteVersion(ctx context.Context, bucketID int, objectKey string, versionNumber int) error {
//		err := obs.objectRepository.HardDeleteObject(ctx, bucketID, objectKey)
//		removePath, err := obs.createDestPath(bucketID, 0, objectKey)
//		if err != nil {
//			return err
//		}
//		return os.Remove(removePath)
//	}
func (obs *ObjectService) Delete(ctx context.Context, bucketID, userID int, objectKey string, versionNumber int, isHardDelete bool) error {
	return nil
}

// 	err := obs.checkExecutePermissions(ctx, bucketID, userID)
// 	if err != nil {
// 		return err
// 	}
//
// 	err = obs.checkDoesBucketExist(ctx, bucketID)
// 	if err != nil {
// 		return err
// 	}
//
// 	isVersioningEnabled, err := obs.bucketRepository.IsVersioningEnabled(ctx, bucketID)
// 	if err != nil {
// 		return err
// 	}
//
// 	if isVersioningEnabled && !isHardDelete {
// 		return obs.objectRepository.SoftDeleteVersion(ctx, bucketID, objectKey, versionNumber)
// 	} else if !isVersioningEnabled && !isHardDelete {
// 		return obs.objectRepository.SoftDeleteObject(ctx, bucketID, objectKey)
// 	} else if !isVersioningEnabled && isHardDelete {
// 		return obs.hardDeleteVersion(ctx, bucketID, objectKey, versionNumber)
// 	} else {
// 		return obs.hardDeleteVersion(ctx, bucketID, objectKey, versionNumber)
// 	}
// }
