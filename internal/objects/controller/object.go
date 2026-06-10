package controller

import (
	"context"
	"errors"
	"net/http"
	"time"

	commonErrors "github.com/slodkiadrianek/MINI-BUCKET/common/errors"
	commonInterfaces "github.com/slodkiadrianek/MINI-BUCKET/common/interfaces"
	"github.com/slodkiadrianek/MINI-BUCKET/common/request"
	dto "github.com/slodkiadrianek/MINI-BUCKET/internal/objects/DTO"
)

type objectService interface {
	Create(ctx context.Context, objectID, bucketID, userID int, fileInfo dto.IncomingFile) error
}

type ObjectController struct {
	loggerService        commonInterfaces.Logger
	authorizationService commonInterfaces.AuthorizationMiddleware
	objectService        objectService
}

func NewObjectRepository(loggerService commonInterfaces.Logger, authorizationService commonInterfaces.AuthorizationMiddleware, objectService objectService) *ObjectController {
	return &ObjectController{
		loggerService:        loggerService,
		authorizationService: authorizationService,
		objectService:        objectService,
	}
}

func (oc *ObjectController) Upload(w http.ResponseWriter, r *http.Request) error {
	ctx, cancel := context.WithTimeout(r.Context(), time.Minute*1000)
	defer cancel()

	r, err := oc.authorizationService.VerifyToken(r)
	if err != nil {
		return err
	}
	userID, err := request.ReadUserIDFromToken(r)
	if err != nil {
		return err
	}

	// bucketIDStr, err := request.ReadParam(r, "bucketID")
	// if err != nil {
	// 	return err
	// }
	bucketID := 1
	// if err != nil {
	// 	return err
	// }
	var objectID int = 0
	// objectIDStr, err := request.ReadParam(r, "objectID")
	// if err != nil {
	// 	objectID = 0
	// } else {
	// 	objectID, err = strconv.Atoi(objectIDStr)
	// 	if err != nil {
	// 		return err
	// 	}
	// }

	const maxUploadSize int64 = 256 << 30 // 32 GB

	r.Body = http.MaxBytesReader(w, r.Body, maxUploadSize)
	defer r.Body.Close()

	contentType := r.Header.Get("Content-Type")
	sizeBytes := r.ContentLength

	incomingFile := dto.IncomingFile{
		ContentType: contentType,
		SizeBytes:   int(sizeBytes),
		File:        r.Body,
	}

	err = oc.objectService.Create(ctx, objectID, bucketID, userID, incomingFile)
	if err != nil {
		if errors.Is(err, context.DeadlineExceeded) {
			oc.loggerService.Info("request timed out", r.URL.Path)
			return commonErrors.NewAPIError(http.StatusRequestTimeout, "")
		}
		return err
	}
	return nil
}
