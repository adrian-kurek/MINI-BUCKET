package middleware

import (
	"net/http"

	"github.com/slodkiadrianek/MINI-BUCKET/internal/common/response"
)

type HTTPFunc func(w http.ResponseWriter, r *http.Request) error

func NewAPIError(statusCode int, message string) *APIError {
	return &APIError{
		StatusCode: statusCode,
		Message:    message,
	}
}

type APIError struct {
	StatusCode int
	Message    string
}

func (ae *APIError) Error() string {
	return ae.Message
}

func Make(f HTTPFunc) http.HandlerFunc {
	return func(w http.ResponseWriter, r *http.Request) {
		if err := f(w, r); err != nil {
			if apiErr, ok := err.(*APIError); ok {
				response.Send(w, apiErr.StatusCode, map[string]string{"message": apiErr.Message})
			} else {
				response.Send(w, 500, map[string]string{"message": err.Error()})
			}
		}
	}
}
