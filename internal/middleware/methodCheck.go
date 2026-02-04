package middleware

import (
	"net/http"

	"github.com/slodkiadrianek/MINI-BUCKET/internal/common/response"
)

func MethodCheckMiddleware(method string) func(http.Handler) http.Handler {
	return func(next http.Handler) http.Handler {
		return methodCheckHandler(next, method)
	}
}

func methodCheckHandler(next http.Handler, method string) http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if method != r.Method {
			response.Send(w, 405, map[string]string{"error": "Not found"})
			return
		}
		if next == nil {
			response.Send(w, 500, map[string]string{"error": "Internal server error"})
			return
		}
		next.ServeHTTP(w, r)
	})
}
