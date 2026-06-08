package service

import (
	"context"

	commonErrors "github.com/slodkiadrianek/MINI-BUCKET/common/errors"
	commonInterfaces "github.com/slodkiadrianek/MINI-BUCKET/common/interfaces"
)

type permissionRepository interface {
	Create(ctx context.Context, bucketID, userID, permission int) (int, error)
	GetPermissionValByUserID(ctx context.Context, bucketID, userID int) (int, error)
	Update(ctx context.Context, permissionID, bucketID, userID, permission int) error
	Delete(ctx context.Context, permissionID, bucketID, userID int) error
}

type PermissionService struct {
	permissionRepository permissionRepository
	logger               commonInterfaces.Logger
}

func NewPermissionRepository(permissionRepository permissionRepository, loggerService commonInterfaces.Logger) *PermissionService {
	return &PermissionService{
		permissionRepository: permissionRepository,
		logger:               loggerService,
	}
}

func (ps *PermissionService) Create(ctx context.Context, bucketID, userID, authorizedUserID, permission int) error {
	permission, err := ps.permissionRepository.GetPermissionValByUserID(ctx, bucketID, authorizedUserID)
	if err != nil {
		return err
	}

	if permission != 7 && permission != 3 && permission != 5 {
		ps.logger.Info("user tried to perform operation which is not allowed for him", authorizedUserID)
		return commonErrors.NewAPIError(403, "you are not allowed to do this action")
	}

	_, err = ps.permissionRepository.Create(ctx, bucketID, userID, permission)
	return err
}

func (ps *PermissionService) Update(ctx context.Context, permissionID, bucketID, userID, authorizedUserID, permission int) error {
	permission, err := ps.permissionRepository.GetPermissionValByUserID(ctx, bucketID, authorizedUserID)
	if err != nil {
		return err
	}

	if permission != 7 && permission != 3 && permission != 5 {
		ps.logger.Info("user tried to perform operation which is not allowed for him", authorizedUserID)
		return commonErrors.NewAPIError(403, "you are not allowed to do this action")
	}

	return ps.permissionRepository.Update(ctx, permissionID, bucketID, userID, permission)
}

func (ps *PermissionService) Delete(ctx context.Context, permissionID, bucketID, userID, authorizedUserID int) error {
	permission, err := ps.permissionRepository.GetPermissionValByUserID(ctx, bucketID, authorizedUserID)
	if err != nil {
		return err
	}

	if permission != 7 && permission != 3 && permission != 5 {
		ps.logger.Info("user tried to perform operation which is not allowed for him", authorizedUserID)
		return commonErrors.NewAPIError(403, "you are not allowed to do this action")
	}

	return ps.permissionRepository.Delete(ctx, bucketID, userID, permission)
}
