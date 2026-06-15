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
	dto "github.com/slodkiadrianek/MINI-BUCKET/internal/objects/DTO"
)

type objectService interface {
	Create(ctx context.Context, objectID, bucketID, userID int, fileInfo dto.IncomingFile) error
}

type ObjectHandler struct {
	loggerService        commonInterfaces.Logger
	authorizationService commonInterfaces.AuthenticationMiddleware
	objectService        objectService
}

func NewObjectRepository(loggerService commonInterfaces.Logger, authorizationService commonInterfaces.AuthenticationMiddleware, objectService objectService) *ObjectHandler {
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
		return err
	}

	var objectID int
	objectIDStr := r.PathValue("objectID")
	if objectIDStr == "" {
		objectID = 0
	} else {
		objectID, err = strconv.Atoi(objectIDStr)
		if err != nil {
			return err
		}
	}

	const maxUploadSize int64 = 256 << 30 // 256 GB

	r.Body = http.MaxBytesReader(w, r.Body, maxUploadSize)
	defer r.Body.Close()

	contentType := r.Header.Get("Content-Type")
	sizeBytes := r.ContentLength

	incomingFile := dto.IncomingFile{
		ContentType: contentType,
		SizeBytes:   int(sizeBytes),
		File:        r.Body,
	}

	err = oh.objectService.Create(ctx, objectID, bucketID, userID, incomingFile)
	if err != nil {
		return oh.handleTimeout(err, r.URL.Path)
	}
	return nil
}
