package mocks

import (
	"context"

	"github.com/slodkiadrianek/MINI-BUCKET/internal/objects/DTO"
	"github.com/slodkiadrianek/MINI-BUCKET/internal/objects/model"
	"github.com/stretchr/testify/mock"
)

type MockObjectService struct {
	mock.Mock
}

func (m *MockObjectService) Upload(ctx context.Context, bucketID, userID int, fileInfo DTO.IncomingFile) error {
	args := m.Called(ctx, bucketID, userID, fileInfo)
	return args.Error(0)
}

func (m *MockObjectService) GetMetadata(
	ctx context.Context,
	bucketID int,
	objectKey string,
	versionID int,
) (model.GetMetadata, error) {
	args := m.Called(ctx, bucketID, objectKey, versionID)
	return args.Get(0).(model.GetMetadata), args.Error(1)
}

func (m *MockObjectService) HasPublicAccess(ctx context.Context, bucketID int) (bool, error) {
	args := m.Called(ctx, bucketID)
	return args.Bool(0), args.Error(1)
}

func (m *MockObjectService) CheckReadPermissions(ctx context.Context, bucketID int, userID int) error {
	args := m.Called(ctx, bucketID, userID)
	return args.Error(0)
}

func (m *MockObjectService) Delete(ctx context.Context, bucketID, userID int, objectKey string, versionID int) error {
	args := m.Called(ctx,bucketID,userID,objectKey,versionID)
	return args.Error(0)
}

