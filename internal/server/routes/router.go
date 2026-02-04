// Package routes holds whole logic associated with router and GroupRouter
package routes

import (
	"context"
	"net/http"

	"github.com/slodkiadrianek/MINI-BUCKET/internal/common/request"
	"github.com/slodkiadrianek/MINI-BUCKET/internal/common/response"
	"github.com/slodkiadrianek/MINI-BUCKET/internal/middleware"
)

type (
	routeKey struct {
		method string
		path   string
	}
)

type (
	Router struct {
		middlewarePreChain []Middleware
		routes             map[routeKey]http.Handler
	}
	Middleware func(http.Handler) http.Handler
)

func NewRouter() *Router {
	return &Router{
		middlewarePreChain: []Middleware{},
		routes:             make(map[routeKey]http.Handler),
	}
}

func (r *Router) Request(route string, method string, fns ...any) {
	middlewares := make([]Middleware, 0, len(r.middlewarePreChain)+len(fns))
	middlewares = append(middlewares, middleware.MethodCheckMiddleware(method))
	var finalHandler middleware.HTTPFunc
	if len(r.middlewarePreChain) > 0 {
		middlewares = append(middlewares, r.middlewarePreChain...)
	}
	for _, el := range fns {
		switch fn := el.(type) {
		case func(http.Handler) http.Handler:
			middlewares = append(middlewares, fn)
		case middleware.HTTPFunc:
			finalHandler = fn
		}
	}
	handler := finalHandler
	for i := len(middlewares) - 1; i >= 0; i-- {
		handler = middlewares[i](handler)
	}
	chainedHandler := handler
	route = request.RemoveLastCharacterFromURL(route)
	r.routes[routeKey{method: method, path: route}] = chainedHandler
}

func (r *Router) ServeHTTP(w http.ResponseWriter, req *http.Request) {
	req.URL.Path = request.RemoveLastCharacterFromURL(req.URL.Path)
	for routeKey, handler := range r.routes {
		if routeKey.method != req.Method {
			continue
		}

		if request.MatchRoute(routeKey.path, req.URL.Path) {
			ctx := context.WithValue(req.Context(), "routeKeyPath", routeKey.path)
			req = req.WithContext(ctx)
			handler.ServeHTTP(w, req)
			return
		}
	}
	response.Send(w, 404, map[string]string{"errorDescription": "Route not found"})
}

func (r *Router) Group(prefix string) *GroupRouter {
	return NewGroupRouter(prefix, r)
}

func (r *Router) USE(fns Middleware) {
	r.middlewarePreChain = append(r.middlewarePreChain, fns)
}

func (r *Router) GET(route string, fns ...any) {
	r.Request(route, http.MethodGet, fns...)
}

func (r *Router) POST(route string, fns ...any) {
	r.Request(route, http.MethodPost, fns...)
}

func (r *Router) PATCH(route string, fns ...any) {
	r.Request(route, http.MethodPatch, fns...)
}

func (r *Router) PUT(route string, fns ...any) {
	r.Request(route, http.MethodPut, fns...)
}

func (r *Router) DELETE(route string, fns ...any) {
	r.Request(route, http.MethodDelete, fns...)
}
