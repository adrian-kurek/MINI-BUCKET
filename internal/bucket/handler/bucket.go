package controller

import (
	"context"
	"errors"
	"net/http"
	"strconv"
	"time"

	commonErrors "github.com/slodkiadrianek/MINI-BUCKET/common/errors"
	commonInterfaces "github.com/slodkiadrianek/MINI-BUCKET/common/interfaces"
	"github.com/slodkiadrianek/MINI-BUCKET/common/middleware"
	"github.com/slodkiadrianek/MINI-BUCKET/common/request"
	"github.com/slodkiadrianek/MINI-BUCKET/common/response"
	bucketDTO "github.com/slodkiadrianek/MINI-BUCKET/internal/bucket/DTO"
)

type bucketService interface {
	Create(ctx context.Context, userID int, bucket bucketDTO.BucketInput) error
	Update(ctx context.Context, bucketID, userID int, bucket bucketDTO.BucketInput) error
}

type BucketHandler struct {
	bucketService bucketService
	authorization commonInterfaces.AuthenticationMiddleware
	loggerService commonInterfaces.Logger
}

func NewBucketHandler(bucketService bucketService, authorization commonInterfaces.AuthenticationMiddleware, loggerService commonInterfaces.Logger) *BucketHandler {
	return &BucketHandler{
		bucketService: bucketService,
		authorization: authorization,
		loggerService: loggerService,
	}
}

func (bh *BucketHandler) handleTimeout(err error, URLPath string) error {
	if errors.Is(err, context.DeadlineExceeded) {
		bh.loggerService.Info("request timed out", URLPath)
		return commonErrors.NewAPIError(http.StatusRequestTimeout, "")
	}
	return err
}

func (bh *BucketHandler) Create(w http.ResponseWriter, r *http.Request) error {
	ctx, cancel := context.WithTimeout(r.Context(), time.Second*2)
	defer cancel()

	reqData, err := request.ReadBody[bucketDTO.BucketInput](r)
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

	err = bh.bucketService.Create(ctx, userID, *reqData)
	if err != nil {
		return bh.handleTimeout(err, r.URL.Path)
	}
	response.Send(w, 201, nil)
	return nil
}

func (bh *BucketHandler) Update(w http.ResponseWriter, r *http.Request) error {
	ctx, cancel := context.WithTimeout(r.Context(), time.Second*2)
	defer cancel()

	reqData, err := request.ReadBody[bucketDTO.BucketInput](r)
	if err != nil {
		return commonErrors.NewAPIError(http.StatusUnprocessableEntity, "provided invalid json format")
	}

	err = middleware.ValidateRequestData(reqData)
	if err != nil {
		return err
	}

	bucketID, err := strconv.Atoi(r.PathValue("bucketID"))
	if err != nil {
		return err
	}

	userID, err := request.ReadUserIDFromToken(r)
	if err != nil {
		return err
	}

	err = bh.bucketService.Update(ctx, bucketID, userID, *reqData)
	if err != nil {
		return bh.handleTimeout(err, r.URL.Path)
	}

	return nil
}
