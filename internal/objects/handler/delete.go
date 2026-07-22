package handler

import (
	"context"
	"net/http"
	"strconv"
	"time"

	commonErrors "github.com/slodkiadrianek/MINI-BUCKET/common/errors"
	"github.com/slodkiadrianek/MINI-BUCKET/common/middleware"
	"github.com/slodkiadrianek/MINI-BUCKET/common/request"
	"github.com/slodkiadrianek/MINI-BUCKET/internal/objects/DTO"
)

func (oh *ObjectHandler) DeleteMany(w http.ResponseWriter, r *http.Request) error {
	deleteTimeout := time.Second * 2000
	ctx, cancel := context.WithTimeout(r.Context(),deleteTimeout)
	defer cancel()

	userID, err := oh.verifyAndGetUserID(r)
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

	reqData, err := request.ReadBody[DTO.DeleteManyFiles](r)
	if err != nil {
		return commonErrors.NewAPIError(http.StatusUnprocessableEntity, "provided invalid json format")
	}

	err = middleware.ValidateRequestData(reqData)
	if err != nil {
		return err
	}

	return nil
}
