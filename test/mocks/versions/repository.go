package mocks

import (
	"context"
	"database/sql"

	"github.com/slodkiadrianek/MINI-BUCKET/internal/versions/DTO"
	"github.com/stretchr/testify/mock"
)

type MockVersionRepository struct {
	mock.Mock
}

func (m *MockVersionRepository) Create(ctx context.Context, tx *sql.Tx, file DTO.Create) (int, error) {
	args := m.Called(ctx, tx, file)
	return args.Int(0), args.Error(1)
}

func (m *MockVersionRepository) GetNewVersionNumber(ctx context.Context, tx *sql.Tx, objectID int) (int, error) {
	args := m.Called(ctx, tx, objectID)
	return args.Int(0), args.Error(1)
}
