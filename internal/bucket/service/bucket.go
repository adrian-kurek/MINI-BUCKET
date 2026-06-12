package service

import (
	"context"

	commonErrors "github.com/slodkiadrianek/MINI-BUCKET/common/errors"
	commonInterfaces "github.com/slodkiadrianek/MINI-BUCKET/common/interfaces"
	bucketDTO "github.com/slodkiadrianek/MINI-BUCKET/internal/bucket/DTO"
)

type bucketRepository interface {
	Create(ctx context.Context, userID int, bucket bucketDTO.BucketInput) (int, error)
	Update(ctx context.Context, bucketID, userID int, bucket bucketDTO.BucketInput) error
}

type permissionRepository interface {
	Create(ctx context.Context, bucketID, userID, permission int) (int, error)
	GetPermissionValByUserID(ctx context.Context, bucketID, userID int) (int, error)
}

type BucketService struct {
	bucketRepository     bucketRepository
	permissionRepository permissionRepository
	logger               commonInterfaces.Logger
}

func NewBucketService(bucketRepository bucketRepository, permissionRepository permissionRepository, loggerService commonInterfaces.Logger) *BucketService {
	return &BucketService{
		bucketRepository:     bucketRepository,
		permissionRepository: permissionRepository,
		logger:               loggerService,
	}
}

func (bs *BucketService) checkPermissions(ctx context.Context, bucketID, userID int) error {
	permission, err := bs.permissionRepository.GetPermissionValByUserID(ctx, bucketID, userID)
	if err != nil {
		return err
	}

	if permission != 7 && permission != 3 && permission != 5 {
		bs.logger.Info("user tried to perform operation which is not allowed for him", userID)
		return commonErrors.NewAPIError(403, "you are not allowed to do this action")
	}
	return nil
}

func (bs *BucketService) Create(ctx context.Context, userID int, bucket bucketDTO.BucketInput) error {
	bucketID, err := bs.bucketRepository.Create(ctx, userID, bucket)
	if err != nil {
		return err
	}
	_, err = bs.permissionRepository.Create(ctx, bucketID, userID, 7)
	return err
}

func (bs *BucketService) Update(ctx context.Context, bucketID, userID int, bucket bucketDTO.BucketInput) error {
	err := bs.checkPermissions(ctx, bucketID, userID)
	if err != nil {
		return err
	}
	return bs.bucketRepository.Update(ctx, bucketID, userID, bucket)
}
