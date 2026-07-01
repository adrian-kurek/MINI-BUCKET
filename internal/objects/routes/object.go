package routes

import (
	"fmt"
	"net/http"

	"github.com/slodkiadrianek/MINI-BUCKET/common/request"
)

type objectHandler interface {
	Upload(w http.ResponseWriter, r *http.Request) error
	GetMetadata(w http.ResponseWriter, r *http.Request) error
}
type ObjectRoutes struct {
	objectHandler objectHandler
}

func New(objectHandler objectHandler) *ObjectRoutes {
	return &ObjectRoutes{
		objectHandler: objectHandler,
	}
}

func (oh *ObjectRoutes) SetupObjectRoutes(router *http.ServeMux) {
	prefix := "/buckets/{bucketID}"
	router.Handle(fmt.Sprintf("PUT %s/objects", prefix), request.Make(oh.objectHandler.Upload))
	router.Handle(fmt.Sprintf("GET %s/objects/{objectKey}", prefix), request.Make(oh.objectHandler.GetMetadata))
}
