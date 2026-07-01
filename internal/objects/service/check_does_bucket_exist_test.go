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

func TestCheckDoesBucketExist(t *testing.T) {
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
				mBucketRepository.On("Exists", mock.Anything, mock.Anything).Return(true, nil)
				return mPermissionRepository, mObjectRepository, mVersionRepository, mBucketRepository
			},
			wantErr: false,
			err:     nil,
		},
		{
			title: "bucket does not exists",
			setupMock: func() (objectService.PermissionRepository, objectService.ObjectRepository, objectService.VersionRepository, objectService.BucketRepository) {
				mPermissionRepository := new(permissionMocks.MockPermissionRepository)
				mObjectRepository := new(objectMocks.MockObjectRepository)
				mVersionRepository := new(versionMocks.MockVersionRepository)
				mBucketRepository := new(bucketMocks.MockBucketRepository)
				mBucketRepository.On("Exists", mock.Anything, mock.Anything).Return(false, nil)
				return mPermissionRepository, mObjectRepository, mVersionRepository, mBucketRepository
			},
			wantErr: true,
			err:     errors.New("api error: bucket with provided id does not exist"),
		},
		{
			title: "failed db query Exists failed ",
			setupMock: func() (objectService.PermissionRepository, objectService.ObjectRepository, objectService.VersionRepository, objectService.BucketRepository) {
				mPermissionRepository := new(permissionMocks.MockPermissionRepository)
				mObjectRepository := new(objectMocks.MockObjectRepository)
				mVersionRepository := new(versionMocks.MockVersionRepository)
				mBucketRepository := new(bucketMocks.MockBucketRepository)
				mBucketRepository.On("Exists", mock.Anything, mock.Anything).
					Return(false, errors.New("failed to perform query"))
				return mPermissionRepository, mObjectRepository, mVersionRepository, mBucketRepository
			},
			wantErr: true,
			err:     errors.New("failed to perform query"),
		},
	}

	for _, testScenario := range testScenarios {
		t.Run(testScenario.title, func(t *testing.T) {
			ctx, cancel := context.WithTimeout(context.Background(), 2*time.Second)
			defer cancel()

			db, _, _ := sqlmock.New(sqlmock.QueryMatcherOption(sqlmock.QueryMatcherRegexp))

			permissionRepository, objectRepository, versionRepository, bucketRepository := testScenario.setupMock()
			loggerService := setupObjectServiceDependencies()
			svc := objectService.New(
				loggerService,
				objectRepository,
				permissionRepository,
				bucketRepository,
				db,
				versionRepository,
			)

			err := svc.CheckDoesBucketExist(ctx, 1)
			if (err != nil) != testScenario.wantErr {
				t.Errorf("CheckDoesBucketExist() error = %v, wantErr = %v", err, testScenario.wantErr)
			}

			if err != nil && testScenario.err != nil {
				if err.Error() != testScenario.err.Error() {
					t.Errorf("CheckDoesBucketExist() error = %v, scenarioError = %v", err, testScenario.err)
				}
			}
		})
	}
}
