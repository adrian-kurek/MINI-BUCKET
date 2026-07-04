package handler

import (
	"context"
	"errors"
	"net/http"
	"strconv"
	"strings"
	"time"

	commonErrors "github.com/slodkiadrianek/MINI-BUCKET/common/errors"
	commonInterfaces "github.com/slodkiadrianek/MINI-BUCKET/common/interfaces"
	"github.com/slodkiadrianek/MINI-BUCKET/common/request"
	"github.com/slodkiadrianek/MINI-BUCKET/common/response"
	DTO "github.com/slodkiadrianek/MINI-BUCKET/internal/objects/DTO"
	"github.com/slodkiadrianek/MINI-BUCKET/internal/objects/model"
)

const objectTimeout = 2 * time.Second

type ObjectService interface {
	Upload(ctx context.Context, bucketID, userID int, fileInfo DTO.IncomingFile) error
	HasPublicAccess(ctx context.Context, bucketID int) (bool, error)
	GetMetadata(ctx context.Context, bucketID int, objectKey string, versionID int) (model.GetMetadata, error)
	CheckReadPermissions(ctx context.Context, bucketID int, userID int) error
 	Delete(ctx context.Context, bucketID, userID int, objectKey string, versionID int) error 
}

type ObjectHandler struct {
	loggerService        commonInterfaces.Logger
	authorizationService commonInterfaces.AuthenticationMiddleware
	objectService        ObjectService
}

func New(
	loggerService commonInterfaces.Logger,
	authorizationService commonInterfaces.AuthenticationMiddleware,
	objectService ObjectService,
) *ObjectHandler {
	return &ObjectHandler{
		loggerService:        loggerService,
		authorizationService: authorizationService,
		objectService:        objectService,
	}
}

func (oh *ObjectHandler) HandleTimeout(err error, URLPath string) error {
	if errors.Is(err, context.DeadlineExceeded) {
		oh.loggerService.Info("request timed out", URLPath)
		return commonErrors.NewAPIError(http.StatusRequestTimeout, "")
	}
	return err
}

func(oh *ObjectHandler) verifyFileName(fileName string ) error {

	if fileName == "" || strings.Contains(
		fileName,
		"/",
	) || strings.Contains(
		fileName,
		"\\",
	) || strings.Contains(
		fileName,
		"..",
	) {
		return commonErrors.NewAPIError(http.StatusBadRequest, "invalid file name")
	}
	return nil
}

func (oh *ObjectHandler) verifyAndGetUserID(r *http.Request) (int,error) {

	r, err := oh.authorizationService.VerifyToken(r)
	if err != nil {
		return 0,err
	}

	userID, err := request.ReadUserIDFromToken(r)
	if err != nil {
		return 0,err
	}
	return userID,nil
}

func (oh *ObjectHandler) Upload(w http.ResponseWriter, r *http.Request) error {
	uploadTimeout := time.Second * 2000
	ctx, cancel := context.WithTimeout(r.Context(), uploadTimeout)
	defer cancel()

	userID,err := oh.verifyAndGetUserID(r)
	if err != nil {
		return err
	}

	bucketID, err := strconv.Atoi(r.PathValue("bucketID"))
	if err != nil {
		return commonErrors.NewAPIError(
			http.StatusUnprocessableEntity,
			"lack of bucketID or provided bucketID is malformed",
		)
	}

	const maxUploadSize int64 = 256 << 30 // 256 GB

	r.Body = http.MaxBytesReader(w, r.Body, maxUploadSize)
	fileName := r.Header.Get("X-Filename")
	defer func() {
		if err := r.Body.Close(); err != nil {
			oh.loggerService.Error("failed to close stream of bytes", err)
		}
	}()

	err = oh.verifyFileName(fileName)
	if err != nil {
		return err
	}

	contentType := r.Header.Get("Content-Type")
	sizeBytes := r.ContentLength

	incomingFile := DTO.IncomingFile{
		ContentType:  contentType,
		SizeBytes:    int(sizeBytes),
		File:         r.Body,
		FileName:     fileName,
		StorageClass: "STANDARD",
	}

	err = oh.objectService.Upload(ctx, bucketID, userID, incomingFile)
	if err != nil {
		return oh.HandleTimeout(err, r.URL.Path)
	}
	return nil
}

func (oh *ObjectHandler) GetMetadata(w http.ResponseWriter, r *http.Request) error {
	ctx, cancel := context.WithTimeout(r.Context(), objectTimeout)
	defer cancel()

	bucketID, err := strconv.Atoi(r.PathValue("bucketID"))
	if err != nil {
		return commonErrors.NewAPIError(
			http.StatusUnprocessableEntity,
			"lack of bucketID or provided bucketID is malformed",
		)
	}

	hasPublicAccess, err := oh.objectService.HasPublicAccess(ctx, bucketID)
	if err != nil {
		return oh.HandleTimeout(err, r.URL.Path)
	}
	userID := 0
	if !hasPublicAccess {
		r, err = oh.authorizationService.VerifyToken(r)
		if err != nil {
			return err
		}
		userID, err = request.ReadUserIDFromToken(r)
		if err != nil {
			return err
		}
		err = oh.objectService.CheckReadPermissions(ctx, bucketID, userID)
		if err != nil {
			return oh.HandleTimeout(err, r.URL.Path)
		}
	}

	objectKey := r.PathValue("objectKey")
	var versionID int
	versionID, err = strconv.Atoi(request.ReadQueryParam(r, "versionID"))
	if err != nil {
		versionID = 0
	}

	metadata, err := oh.objectService.GetMetadata(ctx, bucketID, objectKey, versionID)
	if err != nil {
		return oh.HandleTimeout(err, r.URL.Path)
	}

	response.Send(w, http.StatusOK, map[string]model.GetMetadata{
		"metadata": metadata,
	})

	return nil
}

func (oh *ObjectHandler) Delete(w http.ResponseWriter, r *http.Request) error {
	deleteTimeout := time.Second * 10
	ctx, cancel := context.WithTimeout(r.Context(), deleteTimeout)
	defer cancel()

	userID,err := oh.verifyAndGetUserID(r)
	if err != nil {
		return err
	}

	bucketID, err := strconv.Atoi(r.PathValue("bucketID"))
	if err != nil {
		return commonErrors.NewAPIError(
			http.StatusUnprocessableEntity,
			"lack of bucketID or provided bucketID is malformed",
		)
	}

	versionIDStr := request.ReadQueryParam(r, "versionID")

	var versionID int
	if versionIDStr == "" {
		versionID = 0
	}
	versionID ,err= strconv.Atoi(versionIDStr)
	if err != nil {
		return err
	}

	objectKey := r.PathValue("objectKey")

	err = oh.verifyFileName(objectKey)
	if err != nil {
		return err
	}

	err = oh.objectService.Delete(ctx, bucketID, userID, objectKey, versionID )
	if err != nil {
		return oh.HandleTimeout(err, r.URL.Path)
	}

	response.Send(w, http.StatusNoContent, nil)

	return nil
}
