package model

type AppError struct {
	StatusCode       int
	ErrorCategory    string // create special type for this
	ErrorDescription string
}
