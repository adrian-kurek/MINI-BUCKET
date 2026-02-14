// Package errors holds whole logic of APIErrors
package errors

import (
	"fmt"
)

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

func (apiE *APIError) Error() string {
	return fmt.Sprintf("api error: %d", apiE.StatusCode)
}
