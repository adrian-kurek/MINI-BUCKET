// Package errors holds whole logic of APIErrors
package errors

import (
	"fmt"
	"net/http"
)

type Category string

const (
	CategoryValidation     Category = "VALIDATION"
	CategoryNotFound       Category = "NOT_FOUND"
	CategoryUnauthorized   Category = "UNAUTHORIZED"
	CategoryInternal       Category = "INTERNAL"
	CategoryRequestTimeout Category = "REQUEST_TIMEOUT"
	CategoryDuplicate      Category = "DUPLICATE"
	CategoryPermissions    Category = "PERMISSIONS"
	CategoryMethodNotAllowed    Category = "METHOD_NOT_ALLOWED"
)

func NewAPIError(statusCode int, category Category, message string, isOperational bool) *APIError {
	return &APIError{
		Category:      category,
		StatusCode:    statusCode,
		Message:       message,
		IsOperational: isOperational,
	}
}

type APIError struct {
	Category      Category
	StatusCode    int
	Message       string
	IsOperational bool
}

func (apiE *APIError) Error() string {
	return fmt.Sprintf("api error: %s", apiE.Message)
}

func NotFound(msg string) *APIError {
	return &APIError{Category: CategoryNotFound, StatusCode: http.StatusNotFound, IsOperational: true, Message: msg}
}

func Validation(msg string) *APIError {
	return &APIError{
		Category: CategoryValidation, StatusCode: http.StatusUnprocessableEntity, IsOperational: true, Message: msg,
	}
}

func Unauthorized(msg string) *APIError {
	return &APIError{
		Category: CategoryUnauthorized, StatusCode: http.StatusUnauthorized, IsOperational: true, Message: msg,
	}
}

func RequestTimeout() *APIError {
	return &APIError{
		Category: CategoryUnauthorized, StatusCode: http.StatusUnauthorized, IsOperational: true, Message: "",
	}
}

func Permissions(msg string) *APIError {
	return &APIError{
		Category: CategoryPermissions, StatusCode: http.StatusForbidden, IsOperational: true, Message: msg,
	}
}
