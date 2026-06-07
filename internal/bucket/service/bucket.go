package service

import (
	"context"

	commonInterfaces "github.com/slodkiadrianek/MINI-BUCKET/common/interfaces"
	bucketDTO "github.com/slodkiadrianek/MINI-BUCKET/internal/bucket/DTO"
)

type bucketRepository interface {
	Create(ctx context.Context, userID int, bucket bucketDTO.BucketInput) (int, error)
	CreatePermission(ctx context.Context, bucketID, userID, permission int) (int, error)
	Update(ctx context.Context, bucketID, userID int, bucket bucketDTO.BucketInput) error
}

type BucketService struct {
	bucketRepository bucketRepository
	logger           commonInterfaces.Logger
}

func (bs *BucketService) Create(ctx context.Context, userID int, bucket bucketDTO.BucketInput) error {
	bucketID, err := bs.bucketRepository.Create(ctx, userID, bucket)
	if err != nil {
		return err
	}
	_, err = bs.bucketRepository.CreatePermission(ctx, bucketID, userID, 7)
	return err
}

func (bs *BucketService) Update(ctx context.Context, bucketID, userID int, bucket bucketDTO.BucketInput) error {
	return bs.bucketRepository.Update(ctx, bucketID, userID, bucket)
}
