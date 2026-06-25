package mocks

import (
	"context"
	"database/sql"

	"github.com/slodkiadrianek/MINI-BUCKET/internal/objects/DTO"
	"github.com/slodkiadrianek/MINI-BUCKET/internal/objects/model"
	"github.com/stretchr/testify/mock"
)

type MockObjectRepository struct {
	mock.Mock
}

func (m *MockObjectRepository) Create(ctx context.Context, tx *sql.Tx, file DTO.Create) (int, error) {
	args := m.Called(ctx, tx, file)
	return args.Int(0), args.Error(1)
}

func (m *MockObjectRepository) GetObjectID(ctx context.Context, objectKey string, bucketID int) (bool, int, error) {
	args := m.Called(ctx, objectKey, bucketID)
	return args.Bool(0), args.Int(1), args.Error(2)
}

func (m *MockObjectRepository) Update(ctx context.Context, tx *sql.Tx, file DTO.Update) error {
	args := m.Called(ctx, tx, file)
	return args.Error(0)
}

func (m *MockObjectRepository) UpdateCurrentVersionIDOfObject(ctx context.Context, tx *sql.Tx, objectID int, versionID int) error {
	args := m.Called(ctx, tx, objectID, versionID)
	return args.Error(0)
}

func (m *MockObjectRepository) GetMetadata(ctx context.Context, bucketID int, objectKey string, versionNumber int) (model.GetMetadata, error) {
	args := m.Called(ctx, bucketID, objectKey, versionNumber)
	return args.Get(0).(model.GetMetadata), args.Error(1)
}

func (m *MockObjectRepository) HardDeleteVersion(ctx context.Context, bucketID int, objectKey string, versionNumber int) error {
	args := m.Called(ctx, bucketID, objectKey, versionNumber)
	return args.Error(0)
}

func (m *MockObjectRepository) SoftDeleteVersion(ctx context.Context, bucketID int, objectKey string, versionNumber int) error {
	args := m.Called(ctx, bucketID, objectKey, versionNumber)
	return args.Error(0)
}

func (m *MockObjectRepository) HardDeleteObject(ctx context.Context, bucketID int, objectKey string) error {
	args := m.Called(ctx, bucketID, objectKey)
	return args.Error(0)
}

func (m *MockObjectRepository) SoftDeleteObject(ctx context.Context, bucketID int, objectKey string) error {
	args := m.Called(ctx, bucketID, objectKey)
	return args.Error(0)
}
