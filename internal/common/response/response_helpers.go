// Package response holds whole logic associated with helper functions
package response

import (
	"encoding/json"
	"net/http"
	// "github.com/slodkiadrianek/octopus/internal/models"
)

// func SetError(w http.ResponseWriter, r *http.Request, err error) {
// 	errBucket, ok := r.Context().Value("ErrorBucket").(*models.ErrorBucket)
// 	if ok {
// 		errBucket.Err = err
// 		return
// 	}
// 	Send(w, 500, map[string]string{
// 		"errorCategory":    "Server",
// 		"errorDescription": "internal server error",
// 	})
// }

func Send(w http.ResponseWriter, status int, data any) {
	w.Header().Set("Content-Type", "application/json")
	w.WriteHeader(status)
	if status == 204 {
		return
	}
	err := json.NewEncoder(w).Encode(data)
	if err != nil {
		panic(err)
	}
}
