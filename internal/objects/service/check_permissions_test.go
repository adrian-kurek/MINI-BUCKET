package service_test

import (
	"context"
	"errors"
	"testing"
	"time"

	"github.com/DATA-DOG/go-sqlmock"
	objectService "github.com/slodkiadrianek/MINI-BUCKET/internal/objects/service"
	bucketMocks "github.com/slodkiadrianek/MINI-BUCKET/test/mocks/bucket"
	objectMocks "github.com/slodkiadrianek/MINI-BUCKET/test/mocks/objects"
	permissionMocks "github.com/slodkiadrianek/MINI-BUCKET/test/mocks/permissions"
	versionMocks "github.com/slodkiadrianek/MINI-BUCKET/test/mocks/versions"
	"github.com/stretchr/testify/mock"
)

func TestCheckWritePermissions(t *testing.T) {
	type args struct {
		title     string
		setupMock func() (objectService.PermissionRepository, objectService.ObjectRepository, objectService.VersionRepository, objectService.BucketRepository)
		wantErr   bool
		err       error
	}

	testScenarios := []args{
		{
			title: "with proper data",
			setupMock: func() (objectService.PermissionRepository, objectService.ObjectRepository, objectService.VersionRepository, objectService.BucketRepository) {
				mPermissionRepository := new(permissionMocks.MockPermissionRepository)
				mObjectRepository := new(objectMocks.MockObjectRepository)
				mVersionRepository := new(versionMocks.MockVersionRepository)
				mBucketRepository := new(bucketMocks.MockBucketRepository)
				mPermissionRepository.On("GetPermissionValByUserID", mock.Anything, mock.Anything, mock.Anything).Return(7, nil)
				return mPermissionRepository, mObjectRepository, mVersionRepository, mBucketRepository
			},
			wantErr: false,
			err:     nil,
		},
		{
			title: "user is not allowed to perform an action",
			setupMock: func() (objectService.PermissionRepository, objectService.ObjectRepository, objectService.VersionRepository, objectService.BucketRepository) {
				mPermissionRepository := new(permissionMocks.MockPermissionRepository)
				mPermissionRepository.On("GetPermissionValByUserID", mock.Anything, mock.Anything, mock.Anything).Return(4, nil)
				mObjectRepository := new(objectMocks.MockObjectRepository)
				mVersionRepository := new(versionMocks.MockVersionRepository)
				mBucketRepository := new(bucketMocks.MockBucketRepository)
				return mPermissionRepository, mObjectRepository, mVersionRepository, mBucketRepository
			},
			wantErr: true,
			err:     errors.New("api error: you are not allowed to do this action"),
		},
		{
			title: "GetPermissionValByUserID failed",
			setupMock: func() (objectService.PermissionRepository, objectService.ObjectRepository, objectService.VersionRepository, objectService.BucketRepository) {
				mPermissionRepository := new(permissionMocks.MockPermissionRepository)
				mPermissionRepository.On("GetPermissionValByUserID", mock.Anything, mock.Anything, mock.Anything).Return(0, errors.New("failed to get data from db"))
				mObjectRepository := new(objectMocks.MockObjectRepository)
				mVersionRepository := new(versionMocks.MockVersionRepository)
				mBucketRepository := new(bucketMocks.MockBucketRepository)
				return mPermissionRepository, mObjectRepository, mVersionRepository, mBucketRepository
			},
			wantErr: true,
			err:     errors.New("failed to get data from db"),
		},
	}

	for _, testScenario := range testScenarios {
		t.Run(testScenario.title, func(t *testing.T) {
			ctx, cancel := context.WithTimeout(context.Background(), 2*time.Second)
			defer cancel()

			db, _, _ := sqlmock.New(sqlmock.QueryMatcherOption(sqlmock.QueryMatcherRegexp))

			permissionRepository, objectRepository, versionRepository, bucketRepository := testScenario.setupMock()
			loggerService := setupObjectServiceDependencies()
			objectService := objectService.NewObjectService(loggerService, objectRepository, permissionRepository, bucketRepository, db, versionRepository)

			err := objectService.CheckWritePermissions(ctx, 1, 1)
			if (err != nil) != testScenario.wantErr {
				t.Errorf("CheckPermissions() error = %v, wantErr = %v", err, testScenario.wantErr)
			}

			if err != nil && testScenario.err != nil {
				if err.Error() != testScenario.err.Error() {
					t.Errorf("CheckPermissions() error = %v, scenarioError = %v", err, testScenario.err)
				}
			}
		})
	}
}
