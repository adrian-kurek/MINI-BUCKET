package routes

import (
	"fmt"
	"net/http"

	"github.com/slodkiadrianek/MINI-BUCKET/common/request"
)

type permissionHandler interface {
	Create(w http.ResponseWriter, r *http.Request) error
	Update(w http.ResponseWriter, r *http.Request) error
	Delete(w http.ResponseWriter, r *http.Request) error
}

type PermissionRoutes struct {
	permissionHandler permissionHandler
}

func NewPermissionRoutes(permissionHandler permissionHandler) *PermissionRoutes {
	return &PermissionRoutes{
		permissionHandler: permissionHandler,
	}
}

func (ph *PermissionRoutes) SetupPermissionRoutes(router *http.ServeMux) {
	prefix := "/buckets/{bucketID}/permissions"
	router.Handle(fmt.Sprintf("POST %s", prefix), request.Make(ph.permissionHandler.Create))
	router.Handle(fmt.Sprintf("PUT %s/{permissionID}", prefix), request.Make(ph.permissionHandler.Update))
	router.Handle(fmt.Sprintf("DELETE %s/{permissionID}", prefix), request.Make(ph.permissionHandler.Delete))
}
