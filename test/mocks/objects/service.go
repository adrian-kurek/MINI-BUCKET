package mocks

import (
	"context"

	"github.com/slodkiadrianek/MINI-BUCKET/internal/objects/DTO"
	"github.com/stretchr/testify/mock"
)

type MockObjectService struct {
	mock.Mock
}

func (m *MockObjectService) Create(ctx context.Context, objectID, bucketID, userID int, fileInfo DTO.IncomingFile) error {
	args := m.Called(ctx, objectID, bucketID, userID, fileInfo)
	return args.Error(0)
}
