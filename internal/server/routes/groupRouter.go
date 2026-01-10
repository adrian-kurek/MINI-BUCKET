package routes

import (
	"net/http"
)

type GroupRouter struct {
	prefix string
	router *Router
}

func NewGroupRouter(prefix string, router *Router) *GroupRouter {
	return &GroupRouter{
		prefix: prefix,
		router: router,
	}
}

func (rg *GroupRouter) GET(route string, fns ...any) {
	rg.router.Request(rg.prefix+route, http.MethodGet, fns...)
}

func (rg *GroupRouter) POST(route string, fns ...any) {
	rg.router.Request(rg.prefix+route, http.MethodPost, fns...)
}

func (rg *GroupRouter) PATCH(route string, fns ...any) {
	rg.router.Request(rg.prefix+route, http.MethodPatch, fns...)
}

func (rg *GroupRouter) PUT(route string, fns ...any) {
	rg.router.Request(rg.prefix+route, http.MethodPut, fns...)
}

func (rg *GroupRouter) DELETE(route string, fns ...any) {
	rg.router.Request(rg.prefix+route, http.MethodDelete, fns...)
}
