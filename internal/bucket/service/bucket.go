package service

import (
	commonInterfaces "github.com/slodkiadrianek/MINI-BUCKET/internal/common/interfaces"
)


type bucketRepository interface{

}

type BucketService struct {
	bucketRepository bucketRepository
	logger commonInterfaces.Logger 
}