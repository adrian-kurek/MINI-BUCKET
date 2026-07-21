package service

import (
	"context"
	"net/http"

	commonErrors "github.com/slodkiadrianek/MINI-BUCKET/common/errors"
	commonInterfaces "github.com/slodkiadrianek/MINI-BUCKET/common/interfaces"
	bucketDTO "github.com/slodkiadrianek/MINI-BUCKET/internal/bucket/DTO"
	"github.com/slodkiadrianek/MINI-BUCKET/internal/bucket/model"
)

type BucketRepository interface {
	Create(ctx context.Context, userID int, bucket bucketDTO.BucketInput) (int, error)
	Update(ctx context.Context, bucketID, userID int, bucket bucketDTO.BucketInput) error
	Get(ctx context.Context, bucketID int) (model.Bucket, error)
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

func New(
	bucketRepository BucketRepository,
	permissionRepository PermissionRepository,
	loggerService commonInterfaces.Logger,
) *BucketService {
	return &BucketService{
		bucketRepository:     bucketRepository,
		permissionRepository: permissionRepository,
		loggerService:        loggerService,
	}
}

func (bs *BucketService) CheckExecutePermissions(ctx context.Context, bucketID, userID int) error {
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

func (bs *BucketService) CheckReadPermissions(ctx context.Context, bucketID, userID int) error {
	permission, err := bs.permissionRepository.GetPermissionValByUserID(ctx, bucketID, userID)
	if err != nil {
		return err
	}

	if permission != 7 && permission != 4 && permission != 5 && permission != 6 {
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

func (bs *BucketService) Get(ctx context.Context, bucketID, userID int) (model.Bucket, error) {
	err := bs.CheckExecutePermissions(ctx, bucketID, userID)
	if err != nil {
		return model.Bucket{}, err
	}
	return bs.bucketRepository.Get(ctx, bucketID)
}

func (bs *BucketService) Update(ctx context.Context, bucketID, userID int, bucket bucketDTO.BucketInput) error {
	err := bs.CheckExecutePermissions(ctx, bucketID, userID)
	if err != nil {
		return err
	}
	return bs.bucketRepository.Update(ctx, bucketID, userID, bucket)
}
