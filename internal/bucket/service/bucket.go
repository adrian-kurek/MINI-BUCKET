package service

import (
	"context"

	bucketDTO "github.com/slodkiadrianek/MINI-BUCKET/internal/bucket/DTO"
	commonInterfaces "github.com/slodkiadrianek/MINI-BUCKET/internal/common/interfaces"
)

type bucketRepository interface {
	Create(ctx context.Context, userID int, bucket bucketDTO.CreateBucket) error
}

type BucketService struct {
	bucketRepository bucketRepository
	logger           commonInterfaces.Logger
}

func (bs *BucketService) Create(ctx context.Context, userID int, bucket bucketDTO.CreateBucket) error {
	return bs.bucketRepository.Create(ctx, userID, bucket)
}
