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

type objectService interface {
	Upload(ctx context.Context, bucketID, userID int, fileInfo DTO.IncomingFile) error
	HasPublicAccess(ctx context.Context, bucketID int) (bool, error)
	GetMetadata(ctx context.Context, bucketID int, objectKeyWithVersionNumber string) (model.GetMetadata, error)
	CheckReadPermissions(ctx context.Context, bucketID int, userID int) error
	Delete(ctx context.Context, bucketID, userID int, objectKey string, versionNumber int, isHardDelete bool) error
}

type ObjectHandler struct {
	loggerService        commonInterfaces.Logger
	authorizationService commonInterfaces.AuthenticationMiddleware
	objectService        objectService
}

func NewObjectHandler(loggerService commonInterfaces.Logger, authorizationService commonInterfaces.AuthenticationMiddleware, objectService objectService) *ObjectHandler {
	return &ObjectHandler{
		loggerService:        loggerService,
		authorizationService: authorizationService,
		objectService:        objectService,
	}
}

func (oh *ObjectHandler) handleTimeout(err error, URLPath string) error {
	if errors.Is(err, context.DeadlineExceeded) {
		oh.loggerService.Info("request timed out", URLPath)
		return commonErrors.NewAPIError(http.StatusRequestTimeout, "")
	}
	return err
}

func (oh *ObjectHandler) Upload(w http.ResponseWriter, r *http.Request) error {
	ctx, cancel := context.WithTimeout(r.Context(), time.Minute*1000)
	defer cancel()

	r, err := oh.authorizationService.VerifyToken(r)
	if err != nil {
		return err
	}

	userID, err := request.ReadUserIDFromToken(r)
	if err != nil {
		return err
	}

	bucketID, err := strconv.Atoi(r.PathValue("bucketID"))
	if err != nil {
		return commonErrors.NewAPIError(http.StatusUnprocessableEntity, "lack of bucketID or provided bucketID is malformed")
	}

	const maxUploadSize int64 = 256 << 30 // 256 GB

	r.Body = http.MaxBytesReader(w, r.Body, maxUploadSize)
	fileName := r.Header.Get("X-Filename")
	defer r.Body.Close()

	if fileName == "" || strings.Contains(fileName, "/") || strings.Contains(fileName, "\\") || strings.Contains(fileName, "..") {
		return commonErrors.NewAPIError(http.StatusBadRequest, "invalid file name")
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
		return oh.handleTimeout(err, r.URL.Path)
	}
	return nil
}

func (oh *ObjectHandler) GetMetadata(w http.ResponseWriter, r *http.Request) error {
	ctx, cancel := context.WithTimeout(r.Context(), time.Second*2)
	defer cancel()

	bucketID, err := strconv.Atoi(r.PathValue("bucketID"))
	if err != nil {
		return commonErrors.NewAPIError(http.StatusUnprocessableEntity, "lack of bucketID or provided bucketID is malformed")
	}

	hasPublicAccess, err := oh.objectService.HasPublicAccess(ctx, bucketID)
	if err != nil {
		return oh.handleTimeout(err, r.URL.Path)
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
			return oh.handleTimeout(err, r.URL.Path)
		}
	}

	objectKeyWithVersionNumber := r.PathValue("objectKeyWithVersionNumber")
	metadata, err := oh.objectService.GetMetadata(ctx, bucketID, objectKeyWithVersionNumber)
	if err != nil {
		return oh.handleTimeout(err, r.URL.Path)
	}

	response.Send(w, http.StatusOK, map[string]model.GetMetadata{
		"metadata": metadata,
	})

	return nil
}

func (oh *ObjectHandler) Delete(w http.ResponseWriter, r *http.Request) error {
	ctx, cancel := context.WithTimeout(r.Context(), time.Second*5)
	defer cancel()

	r, err := oh.authorizationService.VerifyToken(r)
	if err != nil {
		return err
	}
	userID, err := request.ReadUserIDFromToken(r)
	if err != nil {
		return err
	}

	bucketID, err := strconv.Atoi(r.PathValue("bucketID"))
	if err != nil {
		return commonErrors.NewAPIError(http.StatusUnprocessableEntity, "lack of bucketID or provided bucketID is malformed")
	}

	objectKey := r.PathValue("objectKey")

	queryVersionNumber := request.ReadQueryParam(r, "versionNumber")
	versionNumber := 0
	if queryVersionNumber != "" {
		versionNumber, err = strconv.Atoi(queryVersionNumber)
		if err != nil {
			return err
		}
	}

	deleteMode := request.ReadQueryParam(r, "typeOfDelete")

	var isHardDelete bool
	switch deleteMode {
	case "", "soft":
		isHardDelete = false
	case "hard":
		isHardDelete = true
	default:
		return commonErrors.NewAPIError(http.StatusUnprocessableEntity, "typeOfDelete must be 'soft' or 'hard'")
	}

	err = oh.objectService.Delete(ctx, bucketID, userID, objectKey, versionNumber, isHardDelete)
	if err != nil {
		return oh.handleTimeout(err, r.URL.Path)
	}

	response.Send(w, http.StatusNoContent, nil)

	return nil
}
