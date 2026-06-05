package controller

import (
	"context"
	"errors"
	"net/http"
	"time"

	bucketDTO "github.com/slodkiadrianek/MINI-BUCKET/internal/bucket/DTO"
	commonErrors "github.com/slodkiadrianek/MINI-BUCKET/internal/common/errors"
	commonInterfaces "github.com/slodkiadrianek/MINI-BUCKET/internal/common/interfaces"
	"github.com/slodkiadrianek/MINI-BUCKET/internal/common/request"
	"github.com/slodkiadrianek/MINI-BUCKET/internal/common/response"
	"github.com/slodkiadrianek/MINI-BUCKET/internal/middleware"
)

type bucketService interface {
	Create(ctx context.Context, userID int, bucket bucketDTO.CreateBucket) error
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

func (bc *BucketController) Create(w http.ResponseWriter, r *http.Request) error {
	ctx, cancel := context.WithTimeout(r.Context(), time.Second*2)
	defer cancel()

	reqData, err := request.ReadBody[bucketDTO.CreateBucket](r)
	if err != nil {
		return commonErrors.NewAPIError(http.StatusUnprocessableEntity, "provided invalid json format")
	}

	err = middleware.ValidateRequestData(reqData)
	if err != nil {
		return err
	}

	userID, err := request.ReadUserIDFromToken(r)
	if err != nil {
		return err
	}

	err = bc.bucketService.Create(ctx, userID, *reqData)
	if err != nil {
		if errors.Is(err, context.DeadlineExceeded) {
			bc.loggerService.Info("request timed out", r.URL.Path)
			return commonErrors.NewAPIError(http.StatusRequestTimeout, "")
		}
		return err
	}
	response.Send(w, 201, nil)
	return nil
}
