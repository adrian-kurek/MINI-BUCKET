package interfaces

import (
	"net/http"

	userModel "github.com/slodkiadrianek/MINI-BUCKET/internal/user/model"
)

type AuthenticationMiddleware interface {
	GenerateRefreshToken() ([]byte, error)
	HashToken(token []byte) string
	GenerateAccessToken(user userModel.User) (string, error)
	VerifyToken(r *http.Request) (*http.Request, error)
	BlacklistUser(r *http.Request) error
}
