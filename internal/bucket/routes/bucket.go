package routes

import (
	"fmt"
	"net/http"

	"github.com/slodkiadrianek/MINI-BUCKET/common/request"
)

type bucketHandler interface {
	Create(w http.ResponseWriter, r *http.Request) error
	Update(w http.ResponseWriter, r *http.Request) error
}

type BucketRoutes struct {
	bucketHandler bucketHandler
}

func NewBucketRoutes(bucketHandler bucketHandler) *BucketRoutes {
	return &BucketRoutes{
		bucketHandler: bucketHandler,
	}
}

func (bh *BucketRoutes) SetupBucketRoutes(router *http.ServeMux) {
	prefix := "/buckets"
	router.Handle(fmt.Sprintf("POST %s", prefix), request.Make(bh.bucketHandler.Create))
	router.Handle(fmt.Sprintf("PUT %s/{bucketID}", prefix), request.Make(bh.bucketHandler.Update))
}
