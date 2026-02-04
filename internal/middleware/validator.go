package middleware

import (
	"bytes"
	"errors"
	"fmt"
	"io"
	"net/http"

	"github.com/go-playground/validator/v10"
	jsonutil "github.com/slodkiadrianek/MINI-BUCKET/internal/common/json_util"
	"github.com/slodkiadrianek/MINI-BUCKET/internal/common/request"
)

func ValidatorMiddleware[validationSchemaType any](typeOfRequestData string) func(http.Handler) http.Handler {
	return func(next http.Handler) http.Handler {
		return validatorHandler[validationSchemaType](next, typeOfRequestData)
	}
}

func validatorHandler[validationSchemaType any](next http.Handler, typeOfRequestData string) http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		switch typeOfRequestData {
		case "body":
			bodyBytes, err := io.ReadAll(r.Body)
			if err != nil {
				// TODO: Error handling
				return
			}
			defer func() {
				if closeErr := r.Body.Close(); closeErr != nil {
					fmt.Sprintf("Error occured during closing request body:%s", closeErr.Error())
				}
			}()
			var dataFromRequest *validationSchemaType
			dataFromRequest, err = jsonutil.UnmarshalData[validationSchemaType](bodyBytes)
			if err != nil {
				// TODO: Error handling
				return
			}
			err = validateRequestData[validationSchemaType](*dataFromRequest)
			if err != nil {
				// TODO: Error handling
				return
			}
			r.Body = io.NopCloser(bytes.NewBuffer(bodyBytes))
		case "params":
			paramsMap, err := request.ReadAllParams(r)
			if err != nil {
				// TODO: Error handling
				return
			}
			paramsBytes, err := jsonutil.MarshalData(paramsMap)
			if err != nil {
				// TODO: Error handling
				return
			}
			var paramDataFromRequest *validationSchemaType
			paramDataFromRequest, err = jsonutil.UnmarshalData[validationSchemaType](paramsBytes)
			if err != nil {
				// TODO: Error handling
				return
			}
			err = validateRequestData[validationSchemaType](*paramDataFromRequest)
			if err != nil {
				// TODO: Error handling
				return
			}

		}
		next.ServeHTTP(w, r)
	})
}

func validateRequestData[validationSchemaType any](dataFromRequest validationSchemaType) error {
	validate := validator.New(validator.WithRequiredStructEnabled())
	err := validate.Struct(dataFromRequest)
	if err != nil {

		var invalidValidationError *validator.InvalidValidationError
		if errors.As(err, &invalidValidationError) {
			fmt.Println(err)
			return nil
		}

		var validateErrs validator.ValidationErrors
		if errors.As(err, &validateErrs) {
			errors := err.(validator.ValidationErrors)
			fmt.Println(errors)
		}

		return nil
	}
	return nil
}
