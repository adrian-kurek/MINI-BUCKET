package mocks

import (
	"context"

	bucketDTO "github.com/slodkiadrianek/MINI-BUCKET/internal/bucket/DTO"
	"github.com/stretchr/testify/mock"
)

type MockBucketRepository struct {
	mock.Mock
}

func (m *MockBucketRepository) Create(ctx context.Context, userID int, bucket bucketDTO.BucketInput) (int, error) {
	args := m.Called(ctx, userID, bucket)
	return args.Int(0), args.Error(1)
}

func (m *MockBucketRepository) Update(ctx context.Context, bucketID, userID int, bucket bucketDTO.BucketInput) error {
	args := m.Called(ctx, bucketID, userID, bucket)
	return args.Error(0)
}

func (m *MockBucketRepository) Exists(ctx context.Context, bucketID int) (bool, error) {
	args := m.Called(ctx, bucketID)
	return args.Bool(0), args.Error(1)
}
