package service

import (
	"context"
	"net/http"

	commonErrors "github.com/slodkiadrianek/MINI-BUCKET/common/errors"
	"github.com/slodkiadrianek/MINI-BUCKET/internal/objects/model"
)

func (obs *ObjectService) CheckReadPermissions(ctx context.Context, bucketID int, userID int) error {
	permission, err := obs.permissionRepository.GetPermissionValByUserID(ctx, bucketID, userID)
	if err != nil {
		return err
	}
	if permission != 4 && permission != 6 && permission != 5 && permission != 7 {
		obs.loggerService.Info("user tried to perform operation which is not allowed for him", userID)
		return commonErrors.NewAPIError(http.StatusForbidden, "you are not allowed to do this action")
	}
	return nil
}

func (obs *ObjectService) GetMetadata(ctx context.Context, bucketID int, objectKey string, versionID int) (model.GetMetadata, error) {
	isVersioningEnabled, err := obs.bucketRepository.IsVersioningEnabled(ctx, bucketID)
	if err != nil {
		return model.GetMetadata{}, err
	}
	if isVersioningEnabled {
		return obs.versionRepository.GetMetadata(ctx, bucketID, objectKey, versionID)
	}
	return obs.objectRepository.GetMetadata(ctx, bucketID, objectKey)
}

func (obs *ObjectService) HasPublicAccess(ctx context.Context, bucketID int) (bool, error) {
	return obs.bucketRepository.GetPrivacyInfo(ctx, bucketID)
}
