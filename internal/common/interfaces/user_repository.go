package interfaces

import (
	"context"

	"github.com/slodkiadrianek/MINI-BUCKET/internal/user/model"
)

type UserRepository interface {
	FindUserByEmail(ctx context.Context, email string) (model.User, error)
}
