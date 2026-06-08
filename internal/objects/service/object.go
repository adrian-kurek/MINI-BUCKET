package service

import (
	"context"
	"io"

	"github.com/google/uuid"
	commonErrors "github.com/slodkiadrianek/MINI-BUCKET/common/errors"
	commonInterfaces "github.com/slodkiadrianek/MINI-BUCKET/common/interfaces"
	dto "github.com/slodkiadrianek/MINI-BUCKET/internal/objects/DTO"
)

type (
	objectRepository     interface{}
	permissionRepository interface {
		GetPermissionValByUserID(ctx context.Context, bucketID, userID int) (int, error)
	}
)

type ObjectService struct {
	loggerService        commonInterfaces.Logger
	objectRepository     objectRepository
	permissionRepository permissionRepository
}

func NewObjectService(loggerService commonInterfaces.Logger, objectRepository objectRepository) *ObjectService {
	return &ObjectService{
		loggerService:    loggerService,
		objectRepository: objectRepository,
	}
}

func (obs *ObjectService) Create(ctx context.Context, userID int, fileInfo dto.Create, body io.Reader) error {
	permission, err := obs.permissionRepository.GetPermissionValByUserID(ctx, fileInfo.BuckeID, userID)
	if err != nil {
		return err
	}

	if permission != 2 && permission != 6 && permission != 3 {
		obs.loggerService.Info("user tried to perform operation which is not allowed for him", userID)
		return commonErrors.NewAPIError(403, "you are not allowed to do this action")
	}

	objectKey := uuid.NewString()

	return nil
}
