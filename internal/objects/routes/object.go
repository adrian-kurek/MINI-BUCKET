package routes

import (
	"fmt"
	"net/http"

	"github.com/slodkiadrianek/MINI-BUCKET/common/request"
)

type objectController interface {
	Upload(w http.ResponseWriter, r *http.Request) error
}
type ObjectRoutes struct {
	objectController objectController
}

func NewObjectRoutes(objectController objectController) *ObjectRoutes {
	return &ObjectRoutes{
		objectController: objectController,
	}
}

func (oh *ObjectRoutes) SetupObjectRoutes(router *http.ServeMux) {
	prefix := "/buckets"
	router.Handle(fmt.Sprintf("PUT %s/{bucketID}/objects/{objectID}", prefix), request.Make(oh.objectController.Upload))
}
