// Package controller hold whole logic associated with controller
package controller

import (
	"net/http"
)

type logger interface {
	Info(message string, data any)
	Error(message string, data any)
	Warning(message string, data any)
}

type AuthController struct {
	loggerService logger
}

func NewAuthController(loggerService logger) *AuthController {
	return &AuthController{
		loggerService: loggerService,
	}
}

func (ac *AuthController) Register(w http.ResponseWriter, r *http.Request) {
}

func (ac *AuthController) Login(w http.ResponseWriter, r *http.Request) {
	err := "Failed to finishe the task"
	http.Error(w, err, 400)
}
