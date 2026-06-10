package routes

import (
	"fmt"
	"net/http"

	"github.com/slodkiadrianek/MINI-BUCKET/common/request"
)

type objectController interface {
	Upload(w http.ResponseWriter, r *http.Request) error
}
type ObjectHandler struct {
	objectController objectController
}

func NewObjectHandler(objectController objectController) *ObjectHandler {
	return &ObjectHandler{
		objectController: objectController,
	}
}

func (oh *ObjectHandler) SetupObjectHandlers(router *http.ServeMux) {
	prefix := "/buckets"
	router.Handle(fmt.Sprintf("PUT %s/{bucketID}/objects", prefix), request.Make(oh.objectController.Upload))
}
