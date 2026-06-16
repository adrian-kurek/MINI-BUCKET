package mocks

import (
	"context"

	"github.com/stretchr/testify/mock"
)

type MockPermissionService struct {
	mock.Mock
}

func (m *MockPermissionService) Create(ctx context.Context, bucketID, userID, authorizedUserID, permission int) error {
	args := m.Called(ctx, bucketID, userID, authorizedUserID, permission)
	return args.Error(0)
}

func (m *MockPermissionService) Update(ctx context.Context, permissionID, bucketID, userID, authorizedUserID, permission int) error {
	args := m.Called(ctx, permissionID, bucketID, userID, authorizedUserID, permission)
	return args.Error(0)
}

func (m *MockPermissionService) Delete(ctx context.Context, permissionID, bucketID, userID, authorizedUserID int) error {
	args := m.Called(ctx, bucketID, userID, authorizedUserID)
	return args.Error(0)
}
