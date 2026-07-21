package mocks

import (
	"context"

	bucketDTO "github.com/slodkiadrianek/MINI-BUCKET/internal/bucket/DTO"
	"github.com/slodkiadrianek/MINI-BUCKET/internal/bucket/model"
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

func (m *MockBucketRepository) GetPrivacyInfo(ctx context.Context, bucketID int) (bool, error) {
	args := m.Called(ctx, bucketID)
	return args.Bool(0), args.Error(1)
}

func (m *MockBucketRepository) IsVersioningEnabled(ctx context.Context, bucketID int) (bool, error) {
	args := m.Called(ctx, bucketID)
	return args.Bool(0), args.Error(1)
}

func (m *MockBucketRepository) UpdateTotalSize(ctx context.Context, bucketID, sizeBytes int) error {
	args := m.Called(ctx, bucketID, sizeBytes)
	return args.Error(0)
}

func (m *MockBucketRepository)	Get(ctx context.Context, bucketID int) (model.Bucket, error) {
	args := m.Called(ctx,bucketID)
	return args.Get(0).(model.Bucket), args.Error(1)
}
