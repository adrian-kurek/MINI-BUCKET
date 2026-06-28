package service

import (
	"context"
	"net/http"

	commonErrors "github.com/slodkiadrianek/MINI-BUCKET/common/errors"
	commonInterfaces "github.com/slodkiadrianek/MINI-BUCKET/common/interfaces"
	bucketDTO "github.com/slodkiadrianek/MINI-BUCKET/internal/bucket/DTO"
)

type BucketRepository interface {
	Create(ctx context.Context, userID int, bucket bucketDTO.BucketInput) (int, error)
	Update(ctx context.Context, bucketID, userID int, bucket bucketDTO.BucketInput) error
}

type PermissionRepository interface {
	Create(ctx context.Context, bucketID, userID, permission int) (int, error)
	GetPermissionValByUserID(ctx context.Context, bucketID, userID int) (int, error)
}

type BucketService struct {
	bucketRepository     BucketRepository
	permissionRepository PermissionRepository
	loggerService        commonInterfaces.Logger
}

func NewBucketService(bucketRepository BucketRepository, permissionRepository PermissionRepository, loggerService commonInterfaces.Logger) *BucketService {
	return &BucketService{
		bucketRepository:     bucketRepository,
		permissionRepository: permissionRepository,
		loggerService:        loggerService,
	}
}

func (bs *BucketService) CheckPermissions(ctx context.Context, bucketID, userID int) error {
	permission, err := bs.permissionRepository.GetPermissionValByUserID(ctx, bucketID, userID)
	if err != nil {
		return err
	}

	if permission != 7 && permission != 3 && permission != 5 {
		bs.loggerService.Info("user tried to perform operation which is not allowed for him", userID)
		return commonErrors.NewAPIError(http.StatusForbidden, "you are not allowed to do this action")
	}
	return nil
}

func (bs *BucketService) Create(ctx context.Context, userID int, bucket bucketDTO.BucketInput) error {
	bucketID, err := bs.bucketRepository.Create(ctx, userID, bucket)
	if err != nil {
		return err
	}
	permission := 7
	_, err = bs.permissionRepository.Create(ctx, bucketID, userID, permission)
	return err
}

func (bs *BucketService) Update(ctx context.Context, bucketID, userID int, bucket bucketDTO.BucketInput) error {
	err := bs.CheckPermissions(ctx, bucketID, userID)
	if err != nil {
		return err
	}
	return bs.bucketRepository.Update(ctx, bucketID, userID, bucket)
}
