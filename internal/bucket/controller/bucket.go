package controller

import (
	"context"
	"errors"
	"net/http"
	"strconv"
	"time"

	commonErrors "github.com/slodkiadrianek/MINI-BUCKET/common/errors"
	commonInterfaces "github.com/slodkiadrianek/MINI-BUCKET/common/interfaces"
	"github.com/slodkiadrianek/MINI-BUCKET/common/request"
	"github.com/slodkiadrianek/MINI-BUCKET/common/response"
	bucketDTO "github.com/slodkiadrianek/MINI-BUCKET/internal/bucket/DTO"
	"github.com/slodkiadrianek/MINI-BUCKET/internal/middleware"
)

type bucketService interface {
	Create(ctx context.Context, userID int, bucket bucketDTO.Upsert) error
	Update(ctx context.Context, bucketID, userID int, bucket bucketDTO.Upsert) error
	Delete(ctx context.Context, bucketID, userID int) error
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

	reqData, err := request.ReadBody[bucketDTO.Upsert](r)
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

func (bc *BucketController) Update(w http.ResponseWriter, r *http.Request) error {
	ctx, cancel := context.WithTimeout(r.Context(), time.Second*2)
	defer cancel()

	reqData, err := request.ReadBody[bucketDTO.Upsert](r)
	if err != nil {
		return commonErrors.NewAPIError(http.StatusUnprocessableEntity, "provided invalid json format")
	}

	err = middleware.ValidateRequestData(reqData)
	if err != nil {
		return err
	}

	bucketIDStr, err := request.ReadParam(r, "bucketID")
	if err != nil {
		return err
	}
	bucketID, err := strconv.Atoi(bucketIDStr)
	if err != nil {
		return err
	}

	userID, err := request.ReadUserIDFromToken(r)
	if err != nil {
		return err
	}

	err = bc.bucketService.Update(ctx, bucketID, userID, *reqData)
	if err != nil {
		if errors.Is(err, context.DeadlineExceeded) {
			bc.loggerService.Info("request timed out", r.URL.Path)
			return commonErrors.NewAPIError(http.StatusRequestTimeout, "")
		}
		return err
	}

	response.Send(w, 204, nil)
	return nil
}

func (bc *BucketController) Delete(w http.ResponseWriter, r *http.Request) error {
	ctx, cancel := context.WithTimeout(r.Context(), time.Second*2)
	defer cancel()

	bucketIDStr, err := request.ReadParam(r, "bucketID")
	if err != nil {
		return err
	}

	bucketID, err := strconv.Atoi(bucketIDStr)
	if err != nil {
		return err
	}

	userID, err := request.ReadUserIDFromToken(r)
	if err != nil {
		return err
	}

	err = bc.bucketService.Delete(ctx, bucketID, userID)
	if err != nil {
		if errors.Is(err, context.DeadlineExceeded) {
			bc.loggerService.Info("request timed out", r.URL.Path)
			return commonErrors.NewAPIError(http.StatusRequestTimeout, "")
		}
		return err
	}

	response.Send(w, 204, nil)
	return nil
}
