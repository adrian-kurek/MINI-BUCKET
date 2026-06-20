package mocks

import (
	"context"

	bucketDTO "github.com/slodkiadrianek/MINI-BUCKET/internal/bucket/DTO"
	"github.com/stretchr/testify/mock"
)

type MockBucketService struct {
	mock.Mock
}

func (m *MockBucketService) Create(ctx context.Context, userID int, bucket bucketDTO.BucketInput) error {
	args := m.Called(ctx, userID, bucket)
	return args.Error(0)
}

func (m *MockBucketService) Update(ctx context.Context, bucketID, userID int, bucket bucketDTO.BucketInput) error {
	args := m.Called(ctx, bucketID, userID, bucket)
	return args.Error(0)
}
