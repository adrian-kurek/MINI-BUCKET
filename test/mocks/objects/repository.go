package mocks

import (
	"context"
	"database/sql"

	"github.com/slodkiadrianek/MINI-BUCKET/internal/objects/DTO"
	"github.com/stretchr/testify/mock"
)

type MockObjectRepository struct {
	mock.Mock
}

func (m *MockObjectRepository) Create(ctx context.Context, tx *sql.Tx, file DTO.Create) (int, error) {
	args := m.Called(ctx, tx, file)
	return args.Int(0), args.Error(1)
}

func (m *MockObjectRepository) GetObjectKey(ctx context.Context, tx *sql.Tx, objectID int) (bool, string, error) {
	args := m.Called(ctx, tx, objectID)
	return args.Bool(0), args.String(1), args.Error(2)
}

func (m *MockObjectRepository) UpdateCurrentVersionIDOfObject(ctx context.Context, tx *sql.Tx, objectID int, versionID int) error {
	args := m.Called(ctx, tx, objectID, versionID)
	return args.Error(0)
}
