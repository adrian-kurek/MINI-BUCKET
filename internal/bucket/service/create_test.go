package service_test

import (
	"context"
	"errors"
	"testing"
	"time"

	DTO "github.com/slodkiadrianek/MINI-BUCKET/internal/bucket/DTO"
	bucketService "github.com/slodkiadrianek/MINI-BUCKET/internal/bucket/service"
	bucketMocks "github.com/slodkiadrianek/MINI-BUCKET/test/mocks/bucket"
	permissionMocks "github.com/slodkiadrianek/MINI-BUCKET/test/mocks/permissions"
	"github.com/stretchr/testify/mock"
)

func TestCreate(t *testing.T) {
	type args struct {
		title     string
		setupMock func() (bucketService.PermissionRepository, bucketService.BucketRepository)
		wantErr   bool
		err       error
	}

	testScenarios := []args{
		{
			title: "with proper data",
			setupMock: func() (bucketService.PermissionRepository, bucketService.BucketRepository) {
				mPermissionRepository := new(permissionMocks.MockPermissionRepository)
				mPermissionRepository.On("Create", mock.Anything, mock.Anything, mock.Anything, mock.Anything).Return(1, nil)
				mBucketRepository := new(bucketMocks.MockBucketRepository)
				mBucketRepository.On("Create", mock.Anything, mock.Anything, mock.Anything).Return(1, nil)
				return mPermissionRepository, mBucketRepository
			},
			wantErr: false,
			err:     nil,
		},
		{
			title: "failed to create new bucket",
			setupMock: func() (bucketService.PermissionRepository, bucketService.BucketRepository) {
				mPermissionRepository := new(permissionMocks.MockPermissionRepository)
				mBucketRepository := new(bucketMocks.MockBucketRepository)
				mBucketRepository.On("Create", mock.Anything, mock.Anything, mock.Anything).Return(0, errors.New("failed to create the new bucket"))
				return mPermissionRepository, mBucketRepository
			},
			wantErr: true,
			err:     errors.New("failed to create the new bucket"),
		},
		{
			title: "failed to create new permission",
			setupMock: func() (bucketService.PermissionRepository, bucketService.BucketRepository) {
				mPermissionRepository := new(permissionMocks.MockPermissionRepository)
				mPermissionRepository.On("Create", mock.Anything, mock.Anything, mock.Anything, mock.Anything).Return(0, errors.New("failed to create the new permission"))
				mBucketRepository := new(bucketMocks.MockBucketRepository)
				mBucketRepository.On("Create", mock.Anything, mock.Anything, mock.Anything).Return(1, nil)
				return mPermissionRepository, mBucketRepository
			},
			wantErr: true,
			err:     errors.New("failed to create the new permission"),
		},
	}

	for _, testScenario := range testScenarios {
		t.Run(testScenario.title, func(t *testing.T) {
			ctx, cancel := context.WithTimeout(context.Background(), 2*time.Second)
			defer cancel()

			permissionRepository, mBucketRepository := testScenario.setupMock()
			loggerService := setupBucketServiceDependencies()
			bucketService := bucketService.NewBucketService(mBucketRepository, permissionRepository, loggerService)

			err := bucketService.Create(ctx, 1, DTO.BucketInput{})
			if (err != nil) != testScenario.wantErr {
				t.Errorf("Create() error = %v, wantErr = %v", err, testScenario.wantErr)
			}

			if err != nil && testScenario.err != nil {
				if err.Error() != testScenario.err.Error() {
					t.Errorf("Create() error = %v, scenarioError = %v", err, testScenario.err)
				}
			}
		})
	}
}
