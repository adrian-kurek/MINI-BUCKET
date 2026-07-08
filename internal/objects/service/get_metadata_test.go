package service_test

import (
	"context"
	"errors"
	"testing"
	"time"

	"github.com/DATA-DOG/go-sqlmock"
	"github.com/slodkiadrianek/MINI-BUCKET/internal/objects/model"
	objectService "github.com/slodkiadrianek/MINI-BUCKET/internal/objects/service"
	bucketMocks "github.com/slodkiadrianek/MINI-BUCKET/test/mocks/bucket"
	objectMocks "github.com/slodkiadrianek/MINI-BUCKET/test/mocks/objects"
	permissionMocks "github.com/slodkiadrianek/MINI-BUCKET/test/mocks/permissions"
	versionMocks "github.com/slodkiadrianek/MINI-BUCKET/test/mocks/versions"
	"github.com/stretchr/testify/mock"
)

func TestCheckReadPermissions(t *testing.T) {
	type args struct {
		title     string
		setupMock func() objectService.PermissionRepository
		wantErr   bool
		err       error
	}

	testScenarios := []args{
		{
			title: "with proper data",
			setupMock: func() objectService.PermissionRepository {
				mPermissionRepository := new(permissionMocks.MockPermissionRepository)
				mPermissionRepository.On("GetPermissionValByUserID", mock.Anything, mock.Anything, mock.Anything).Return(7, nil)
				return mPermissionRepository
			},
			wantErr: false,
			err:     nil,
		},
		{
			title: "GetPermissionValByUserID failed",
			setupMock: func() objectService.PermissionRepository {
				mPermissionRepository := new(permissionMocks.MockPermissionRepository)
				mPermissionRepository.On("GetPermissionValByUserID", mock.Anything, mock.Anything, mock.Anything).Return(0, errors.New("failed to perform query"))
				return mPermissionRepository
			},
			wantErr: true,
			err:     errors.New("failed to perform query"),
		},
		{
			title: "user is not allowed to perform an action",
			setupMock: func() objectService.PermissionRepository {
				mPermissionRepository := new(permissionMocks.MockPermissionRepository)
				mPermissionRepository.On("GetPermissionValByUserID", mock.Anything, mock.Anything, mock.Anything).Return(2, nil)
				return mPermissionRepository
			},
			wantErr: true,
			err:     errors.New("api error: you are not allowed to do this action"),
		},
	}

	for _, testScenario := range testScenarios {
		t.Run(testScenario.title, func(t *testing.T) {
			ctx, cancel := context.WithTimeout(context.Background(), 2*time.Second)
			defer cancel()
			db, _, _ := sqlmock.New(sqlmock.QueryMatcherOption(sqlmock.QueryMatcherRegexp))

			bucketRepository := new(bucketMocks.MockBucketRepository)
			objectRepository := new(objectMocks.MockObjectRepository)
			versionRepository := new(versionMocks.MockVersionRepository)
			permissionRepository := testScenario.setupMock()
			loggerService := setupObjectServiceDependencies()

			svc := objectService.New(
				loggerService,
				objectRepository,
				permissionRepository,
				bucketRepository,
				db,
				versionRepository,
			)

			err := svc.CheckReadPermissions(ctx, 1, 1)
			if (err != nil) != testScenario.wantErr {
				t.Errorf("CheckReadPermissions() error = %v, wantErr = %v", err, testScenario.wantErr)
			}

			if err != nil && testScenario.err != nil {
				if err.Error() != testScenario.err.Error() {
					t.Errorf("CheckReadPermissions() error = %v, scenarioError = %v", err, testScenario.err)
				}
			}
		})
	}
}

func TestGetMetadata(t *testing.T) {
	type args struct {
		title     string
		setupMock func() (objectService.BucketRepository, objectService.VersionRepository, objectService.ObjectRepository)
		wantErr   bool
		err       error
	}

	testScenarios := []args{
		{
			title: "with proper data, with versioning enabled",
			setupMock: func() (objectService.BucketRepository, objectService.VersionRepository, objectService.ObjectRepository) {
				mObjectRepository := new(objectMocks.MockObjectRepository)
				mVersionRepository := new(versionMocks.MockVersionRepository)
				mVersionRepository.On("GetMetadata", mock.Anything, mock.Anything, mock.Anything, mock.Anything).Return(model.GetMetadata{}, nil)
				mBucketRepository := new(bucketMocks.MockBucketRepository)
				mBucketRepository.On("IsVersioningEnabled", mock.Anything, mock.Anything).Return(true, nil)
				return mBucketRepository, mVersionRepository, mObjectRepository
			},
			wantErr: false,
			err:     nil,
		},
		{
			title: "with proper data, without versioning enabled",
			setupMock: func() (objectService.BucketRepository, objectService.VersionRepository, objectService.ObjectRepository) {
				mObjectRepository := new(objectMocks.MockObjectRepository)
				mObjectRepository.On("GetMetadata", mock.Anything, mock.Anything, mock.Anything).Return(model.GetMetadata{}, nil)
				mVersionRepository := new(versionMocks.MockVersionRepository)
				mBucketRepository := new(bucketMocks.MockBucketRepository)
				mBucketRepository.On("IsVersioningEnabled", mock.Anything, mock.Anything).Return(false, nil)
				return mBucketRepository, mVersionRepository, mObjectRepository
			},
			wantErr: false,
			err:     nil,
		},
		{
			title: "IsVersioningEnabled failed",
			setupMock: func() (objectService.BucketRepository, objectService.VersionRepository, objectService.ObjectRepository) {
				mObjectRepository := new(objectMocks.MockObjectRepository)
				mVersionRepository := new(versionMocks.MockVersionRepository)
				mBucketRepository := new(bucketMocks.MockBucketRepository)
				mBucketRepository.On("IsVersioningEnabled", mock.Anything, mock.Anything).Return(false, errors.New("failed to perform query"))
				return mBucketRepository, mVersionRepository, mObjectRepository
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

			permissionRepository := new(permissionMocks.MockPermissionRepository)
			bucketRepository, versionRepository, objectRepository := testScenario.setupMock()
			loggerService := setupObjectServiceDependencies()

			svc := objectService.New(
				loggerService,
				objectRepository,
				permissionRepository,
				bucketRepository,
				db,
				versionRepository,
			)

			_, err := svc.GetMetadata(ctx, 1, "test", 1)
			if (err != nil) != testScenario.wantErr {
				t.Errorf("GetMetadata() error = %v, wantErr = %v", err, testScenario.wantErr)
			}

			if err != nil && testScenario.err != nil {
				if err.Error() != testScenario.err.Error() {
					t.Errorf("GetMetadata() error = %v, scenarioError = %v", err, testScenario.err)
				}
			}
		})
	}
}

func TestHasPublicAccess(t *testing.T) {
	type args struct {
		title     string
		setupMock func() objectService.BucketRepository
		wantErr   bool
		err       error
	}

	testScenarios := []args{
		{
			title: "with proper data",
			setupMock: func() objectService.BucketRepository {
				mBucketRepository := new(bucketMocks.MockBucketRepository)
				mBucketRepository.On("GetPrivacyInfo", mock.Anything, mock.Anything).Return(true, nil)
				return mBucketRepository
			},
			wantErr: false,
			err:     nil,
		},
		{
			title: "GetPrivacyInfo failed",
			setupMock: func() objectService.BucketRepository {
				mBucketRepository := new(bucketMocks.MockBucketRepository)
				mBucketRepository.On("GetPrivacyInfo", mock.Anything, mock.Anything).Return(false, errors.New("failed to perform query"))
				return mBucketRepository
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

		
			permissionRepository := new(permissionMocks.MockPermissionRepository)
			objectRepository := new(objectMocks.MockObjectRepository)
			versionRepository := new(versionMocks.MockVersionRepository)
			bucketRepository := testScenario.setupMock()
			loggerService := setupObjectServiceDependencies()

			svc := objectService.New(
				loggerService,
				objectRepository,
				permissionRepository,
				bucketRepository,
				db,
				versionRepository,
			)

			_, err := svc.HasPublicAccess(ctx, 1)
			if (err != nil) != testScenario.wantErr {
				t.Errorf("HasPublicAccess() error = %v, wantErr = %v", err, testScenario.wantErr)
			}

			if err != nil && testScenario.err != nil {
				if err.Error() != testScenario.err.Error() {
					t.Errorf("HasPublicAccess() error = %v, scenarioError = %v", err, testScenario.err)
				}
			}
		})
	}
}
