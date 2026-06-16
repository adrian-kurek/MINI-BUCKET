package mocks

import (
	"context"

	"github.com/stretchr/testify/mock"
)

type MockPermissionRepository struct {
	mock.Mock
}

func (m *MockPermissionRepository) Create(ctx context.Context, bucketID, userID, permission int) (int, error) {
	args := m.Called(ctx, bucketID, userID, permission)
	return args.Int(0), args.Error(1)
}

func (m *MockPermissionRepository) GetPermissionValByUserID(ctx context.Context, bucketID, userID int) (int, error) {
	args := m.Called(ctx, bucketID, userID)
	return args.Int(0), args.Error(1)
}

func (m *MockPermissionRepository) Update(ctx context.Context, permissionID, bucketID, userID, permission int) error {
	args := m.Called(ctx, permissionID, bucketID, userID, permission)
	return args.Error(0)
}

func (m *MockPermissionRepository) Delete(ctx context.Context, permissionID, bucketID, userID int) error {
	args := m.Called(ctx, permissionID, bucketID, userID)
	return args.Error(0)
}
