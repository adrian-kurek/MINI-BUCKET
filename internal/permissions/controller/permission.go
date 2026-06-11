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
	dto "github.com/slodkiadrianek/MINI-BUCKET/internal/permissions/DTO"
)

type permissionService interface {
	Create(ctx context.Context, bucketID, userID, authorizedUserID, permission int) error
	Update(ctx context.Context, permissionID, bucketID, userID, authorizedUserID, permission int) error
	Delete(ctx context.Context, permissionID, bucketID, userID, authorizedUserID int) error
}
type PermissionController struct {
	permissionService permissionService
	authorization     commonInterfaces.AuthenticationMiddleware
	loggerService     commonInterfaces.Logger
}

func NewPermissionController(permissionService permissionService, authorizationService commonInterfaces.AuthenticationMiddleware, loggerService commonInterfaces.Logger) *PermissionController {
	return &PermissionController{
		permissionService: permissionService,
		authorization:     authorizationService,
		loggerService:     loggerService,
	}
}

func (pc *PermissionController) Create(w http.ResponseWriter, r *http.Request) error {
	ctx, cancel := context.WithTimeout(r.Context(), time.Second*2)
	defer cancel()

	reqData, err := request.ReadBody[dto.Upsert](r)
	if err != nil {
		return commonErrors.NewAPIError(http.StatusUnprocessableEntity, "provided invalid json format")
	}

	err = middleware.ValidateRequestData(reqData)
	if err != nil {
		return err
	}

	authorizedUserID, err := request.ReadUserIDFromToken(r)
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

	err = pc.permissionService.Create(ctx, bucketID, reqData.UserID, authorizedUserID, reqData.Permission)
	if err != nil {
		if errors.Is(err, context.DeadlineExceeded) {
			pc.loggerService.Info("request timed out", r.URL.Path)
			return commonErrors.NewAPIError(http.StatusRequestTimeout, "")
		}
		return err
	}

	return nil
}

func (pc *PermissionController) Update(w http.ResponseWriter, r *http.Request) error {
	ctx, cancel := context.WithTimeout(r.Context(), time.Second*2)
	defer cancel()

	reqData, err := request.ReadBody[dto.Upsert](r)
	if err != nil {
		return commonErrors.NewAPIError(http.StatusUnprocessableEntity, "provided invalid json format")
	}

	err = middleware.ValidateRequestData(reqData)
	if err != nil {
		return err
	}

	authorizedUserID, err := request.ReadUserIDFromToken(r)
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

	permissionIDStr, err := request.ReadParam(r, "permissionID")
	if err != nil {
		return err
	}

	permissionID, err := strconv.Atoi(permissionIDStr)
	if err != nil {
		return err
	}

	err = pc.permissionService.Update(ctx, permissionID, bucketID, reqData.UserID, authorizedUserID, reqData.Permission)
	if err != nil {
		if errors.Is(err, context.DeadlineExceeded) {
			pc.loggerService.Info("request timed out", r.URL.Path)
			return commonErrors.NewAPIError(http.StatusRequestTimeout, "")
		}
		return err
	}

	return nil
}

func (pc *PermissionController) Delete(w http.ResponseWriter, r *http.Request) error {
	ctx, cancel := context.WithTimeout(r.Context(), time.Second*2)
	defer cancel()

	reqData, err := request.ReadBody[dto.Delete](r)
	if err != nil {
		return commonErrors.NewAPIError(http.StatusUnprocessableEntity, "provided invalid json format")
	}

	err = middleware.ValidateRequestData(reqData)
	if err != nil {
		return err
	}

	authorizedUserID, err := request.ReadUserIDFromToken(r)
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

	permissionIDStr, err := request.ReadParam(r, "permissionID")
	if err != nil {
		return err
	}

	permissionID, err := strconv.Atoi(permissionIDStr)
	if err != nil {
		return err
	}

	err = pc.permissionService.Delete(ctx, permissionID, bucketID, reqData.UserID, authorizedUserID)
	if err != nil {
		if errors.Is(err, context.DeadlineExceeded) {
			pc.loggerService.Info("request timed out", r.URL.Path)
			return commonErrors.NewAPIError(http.StatusRequestTimeout, "")
		}
		return err
	}

	return nil
}
