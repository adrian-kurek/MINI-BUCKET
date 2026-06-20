package service

import (
	"context"
	"errors"
	"testing"
	"time"

	dto "github.com/slodkiadrianek/MINI-BUCKET/internal/bucket/DTO"
	bucketMocks "github.com/slodkiadrianek/MINI-BUCKET/test/mocks/bucket"
	permissionMocks "github.com/slodkiadrianek/MINI-BUCKET/test/mocks/permissions"
	"github.com/stretchr/testify/mock"
)

func TestUpdate(t *testing.T) {
	type args struct {
		title     string
		setupMock func() (permissionRepository, bucketRepository)
		wantErr   bool
		err       error
	}
	testScenarios := []args{
		{
			title: "with proper data",
			setupMock: func() (permissionRepository, bucketRepository) {
				mPermissionRepository := new(permissionMocks.MockPermissionRepository)
				mPermissionRepository.On("GetPermissionValByUserID", mock.Anything, mock.Anything, mock.Anything).Return(7, nil)
				mBucketRepository := new(bucketMocks.MockBucketRepository)
				mBucketRepository.On("Update", mock.Anything, mock.Anything, mock.Anything, mock.Anything).Return(nil)

				return mPermissionRepository, mBucketRepository
			},
			wantErr: false,
			err:     nil,
		},
		{
			title: "failed to check permissions",
			setupMock: func() (permissionRepository, bucketRepository) {
				mPermissionRepository := new(permissionMocks.MockPermissionRepository)
				mPermissionRepository.On("GetPermissionValByUserID", mock.Anything, mock.Anything, mock.Anything).Return(0, errors.New("failed to check permissions"))
				mBucketRepository := new(bucketMocks.MockBucketRepository)

				return mPermissionRepository, mBucketRepository
			},
			wantErr: true,
			err:     errors.New("failed to check permissions"),
		},
		{
			title: "failed to update",
			setupMock: func() (permissionRepository, bucketRepository) {
				mPermissionRepository := new(permissionMocks.MockPermissionRepository)
				mPermissionRepository.On("GetPermissionValByUserID", mock.Anything, mock.Anything, mock.Anything).Return(7, nil)
				mBucketRepository := new(bucketMocks.MockBucketRepository)
				mBucketRepository.On("Update", mock.Anything, mock.Anything, mock.Anything, mock.Anything).Return(errors.New("failed to update"))

				return mPermissionRepository, mBucketRepository
			},
			wantErr: true,
			err:     errors.New("failed to update"),
		},
	}

	for _, testScenario := range testScenarios {
		t.Run(testScenario.title, func(t *testing.T) {
			ctx, cancel := context.WithTimeout(context.Background(), 2*time.Second)
			defer cancel()

			permissionRepository, mBucketRepository := testScenario.setupMock()
			loggerService := setupBucketServiceDependencies()
			bucketService := NewBucketService(mBucketRepository, permissionRepository, loggerService)

			err := bucketService.Update(ctx, 1, 1, dto.BucketInput{})
			if (err != nil) != testScenario.wantErr {
				t.Errorf("Update() error = %v, wantErr = %v", err, testScenario.wantErr)
			}

			if err != nil && testScenario.err != nil {
				if err.Error() != testScenario.err.Error() {
					t.Errorf("Update() error = %v, scenarioError = %v", err, testScenario.err)
				}
			}
		})
	}
}
