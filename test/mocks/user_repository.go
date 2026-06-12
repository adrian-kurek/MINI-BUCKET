package mocks

import (
	"context"

	"github.com/slodkiadrianek/MINI-BUCKET/internal/user/model"
	authDTO	"github.com/slodkiadrianek/MINI-BUCKET/internal/auth/DTO"

	"github.com/stretchr/testify/mock"
)

type MockUserRepository struct {
	mock.Mock
}

func (m *MockUserRepository) Create(ctx context.Context, user authDTO.CreateUser, hashedPassword []byte) error {
	args := m.Called(ctx, user, hashedPassword)
	return args.Error(0)
}

func (m *MockUserRepository) FindByEmail(ctx context.Context, email string) (model.User, error) {
	args := m.Called(ctx, email)
	return args.Get(0).(model.User), args.Error(1)
}
