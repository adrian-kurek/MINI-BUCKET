package service

import (
	"context"

	commonInterfaces "github.com/slodkiadrianek/MINI-BUCKET/common/interfaces"
	bucketDTO "github.com/slodkiadrianek/MINI-BUCKET/internal/bucket/DTO"
)

type bucketRepository interface {
	Create(ctx context.Context, userID int, bucket bucketDTO.Upsert) (int, error)
	Update(ctx context.Context, bucketID, userID int, bucket bucketDTO.Upsert) error
}
type permissinRepository interface {
	Create(ctx context.Context, bucketID, userID, permission int) (int, error)
}

type BucketService struct {
	bucketRepository     bucketRepository
	permissionRepository permissinRepository
	logger               commonInterfaces.Logger
}

func (bs *BucketService) Create(ctx context.Context, userID int, bucket bucketDTO.Upsert) error {
	bucketID, err := bs.bucketRepository.Create(ctx, userID, bucket)
	if err != nil {
		return err
	}
	_, err = bs.permissionRepository.Create(ctx, bucketID, userID, 7)
	return err
}

func (bs *BucketService) Update(ctx context.Context, bucketID, userID int, bucket bucketDTO.Upsert) error {
	return bs.bucketRepository.Update(ctx, bucketID, userID, bucket)
}
