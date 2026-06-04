package controller

import (
	"net/http"

	commonInterfaces "github.com/slodkiadrianek/MINI-BUCKET/internal/common/interfaces"
)

type bucketService interface{

}


type BucketController struct {
	bucketService bucketService
	authorization commonInterfaces.AuthorizationMiddleware
	loggerService commonInterfaces.Logger
}


func NewBucketController(bucketService bucketService, authorization commonInterfaces.AuthorizationMiddleware, loggerService commonInterfaces.Logger) *BucketController {
	return &BucketController{
		bucketService: bucketService,
		authorization: authorization,
		loggerService: loggerService,
	}
}

func (bc *BucketController) CreateBucket(w http.ResponseWriter, r *http.Request) error {
	
}