package service_test

import (
	"context"
	"errors"
	"testing"

	"github.com/DATA-DOG/go-sqlmock"
	"github.com/slodkiadrianek/MINI-BUCKET/internal/objects/model"
	objectService "github.com/slodkiadrianek/MINI-BUCKET/internal/objects/service"
	bucketMocks "github.com/slodkiadrianek/MINI-BUCKET/test/mocks/bucket"
	objectMocks "github.com/slodkiadrianek/MINI-BUCKET/test/mocks/objects"
	permissionMocks "github.com/slodkiadrianek/MINI-BUCKET/test/mocks/permissions"
	versionMocks "github.com/slodkiadrianek/MINI-BUCKET/test/mocks/versions"
	"github.com/stretchr/testify/mock"
)

func TestCheckIsVersionDeleted(t *testing.T) {
	type args struct {
		title     string
		isDeleted bool
		versionID int
		wantErr   bool
		err       error
	}
	testScenarios := []args{
		{
			title:     "version not deleted",
			isDeleted: false,
			wantErr:   false,
			err:       nil,
		},
		{
			title:     "version deleted without specified versionID",
			isDeleted: true,
			wantErr:   true,
			err:       errors.New("api error: "),
		},
		{
			title:     "version deleted witht specified versionID",
			isDeleted: true,
			versionID: 1,
			wantErr:   true,
			err:       errors.New("api error: "),
		},
	}

	for _, testScenario := range testScenarios {
		t.Run(testScenario.title, func(t *testing.T) {
			db, _, _ := sqlmock.New(sqlmock.QueryMatcherOption(sqlmock.QueryMatcherRegexp))

			bucketRepository := new(bucketMocks.MockBucketRepository)
			objectRepository := new(objectMocks.MockObjectRepository)
			versionRepository := new(versionMocks.MockVersionRepository)
			permissionRepository := new(permissionMocks.MockPermissionRepository)
			loggerService := setupObjectServiceDependencies()

			svc := objectService.New(
				loggerService,
				objectRepository,
				permissionRepository,
				bucketRepository,
				db,
				versionRepository,
			)

			err := svc.CheckIsVersionDeleted(testScenario.isDeleted, testScenario.versionID)
			if (err != nil) != testScenario.wantErr {
				t.Errorf("CheckIsVersionDeleted() error = %v, wantErr = %v", err, testScenario.wantErr)
			}

			if err != nil && testScenario.err != nil {
				if err.Error() != testScenario.err.Error() {
					t.Errorf("CheckIsVersionDeleted() error = %v, scenarioError = %v", err, testScenario.err)
				}
			}
		})
	}
}

func TestGetWithVersioningEnabled(t *testing.T) {
	type args struct {
		title     string
		setupMock func() objectService.VersionRepository
		wantErr   bool
		err       error
	}
	testScenarios := []args{
		{
			title: "with proper data",
			setupMock: func() objectService.VersionRepository {
				mVersionRepository := new(versionMocks.MockVersionRepository)
				mVersionRepository.On("GetMetadata", mock.Anything, mock.Anything, mock.Anything, mock.Anything).
					Return(model.GetMetadata{ContentType: "text", ETAG: "zaqwewqewq", SizeBytes: 1, IsDeleted: false}, nil)
				mVersionRepository.On("GetUUIDByObjectKey", mock.Anything, mock.Anything, mock.Anything).
					Return("test", nil)

				return mVersionRepository
			},
			wantErr: false,
			err:     nil,
		},
		{
			title: "GetUUIDByObjectKey failed",
			setupMock: func() objectService.VersionRepository {
				mVersionRepository := new(versionMocks.MockVersionRepository)
				mVersionRepository.On("GetMetadata", mock.Anything, mock.Anything, mock.Anything, mock.Anything).
					Return(model.GetMetadata{ContentType: "text", ETAG: "zaqwewqewq", SizeBytes: 1, IsDeleted: false}, nil)
				mVersionRepository.On("GetUUIDByObjectKey", mock.Anything, mock.Anything, mock.Anything).
					Return("", errors.New("failed to perform query"))

				return mVersionRepository
			},
			wantErr: true,
			err:     errors.New("failed to perform query"),
		},
		{
			title: "CheckIsVersionDeleted failed",
			setupMock: func() objectService.VersionRepository {
				mVersionRepository := new(versionMocks.MockVersionRepository)
				mVersionRepository.On("GetMetadata", mock.Anything, mock.Anything, mock.Anything, mock.Anything).
					Return(model.GetMetadata{ContentType: "text", ETAG: "zaqwewqewq", SizeBytes: 1, IsDeleted: true}, nil)

				return mVersionRepository
			},
			wantErr: true,
			err:     errors.New("api error: "),
		},
		{
			title: "GetMetadata failed",
			setupMock: func() objectService.VersionRepository {
				mVersionRepository := new(versionMocks.MockVersionRepository)
				mVersionRepository.On("GetMetadata", mock.Anything, mock.Anything, mock.Anything, mock.Anything).
					Return(model.GetMetadata{}, errors.New("failed to perform query"))
				return mVersionRepository
			},
			wantErr: true,
			err:     errors.New("failed to perform query"),
		},
	}

	for _, testScenario := range testScenarios {
		t.Run(testScenario.title, func(t *testing.T) {
			ctx := context.Background()
			db, _, _ := sqlmock.New(sqlmock.QueryMatcherOption(sqlmock.QueryMatcherRegexp))

			bucketRepository := new(bucketMocks.MockBucketRepository)
			objectRepository := new(objectMocks.MockObjectRepository)
			versionRepository := testScenario.setupMock()
			permissionRepository := new(permissionMocks.MockPermissionRepository)
			loggerService := setupObjectServiceDependencies()

			svc := objectService.New(
				loggerService,
				objectRepository,
				permissionRepository,
				bucketRepository,
				db,
				versionRepository,
			)

			_, _, err := svc.GetWithVersioningEnabled(ctx, "test", 1, 1)
			if (err != nil) != testScenario.wantErr {
				t.Errorf("GetWithVersioningEnabled() error = %v, wantErr = %v", err, testScenario.wantErr)
			}

			if err != nil && testScenario.err != nil {
				if err.Error() != testScenario.err.Error() {
					t.Errorf("GetWithVersioningEnabled() error = %v, scenarioError = %v", err, testScenario.err)
				}
			}
		})
	}
}

func TestGetWithVersioningDisabled(t *testing.T) {
	type args struct {
		title     string
		setupMock func() objectService.ObjectRepository
		wantErr   bool
		err       error
	}
	testScenarios := []args{
		{
			title: "with proper data",
			setupMock: func() objectService.ObjectRepository {
				mObjectRepository := new(objectMocks.MockObjectRepository)
				mObjectRepository.On("GetUUIDByID", mock.Anything, mock.Anything, mock.Anything).
					Return("test", nil)
				mObjectRepository.On("GetMetadata", mock.Anything, mock.Anything, mock.Anything).
					Return(model.GetMetadata{ContentType: "text", SizeBytes: 1, ETAG: "test"}, nil)
				return mObjectRepository
			},
			wantErr: false,
			err:     nil,
		},
		{
			title: "GetMetadata failed",
			setupMock: func() objectService.ObjectRepository {
				mObjectRepository := new(objectMocks.MockObjectRepository)
				mObjectRepository.On("GetUUIDByID", mock.Anything, mock.Anything, mock.Anything).
					Return("test", nil)
				mObjectRepository.On("GetMetadata", mock.Anything, mock.Anything, mock.Anything).
					Return(model.GetMetadata{}, errors.New("failed to perform query"))
				return mObjectRepository
			},
			wantErr: true,
			err:     errors.New("failed to perform query"),
		},
		{
			title: "GetUUIDByID failed",
			setupMock: func() objectService.ObjectRepository {
				mObjectRepository := new(objectMocks.MockObjectRepository)
				mObjectRepository.On("GetUUIDByID", mock.Anything, mock.Anything, mock.Anything).
					Return("", errors.New("failed to perform query"))
				mObjectRepository.On("GetMetadata", mock.Anything, mock.Anything, mock.Anything).
					Return(model.GetMetadata{ContentType: "text", SizeBytes: 1, ETAG: "test"}, nil)
				return mObjectRepository
			},
			wantErr: true,
			err:     errors.New("failed to perform query"),
		},
	}

	for _, testScenario := range testScenarios {
		t.Run(testScenario.title, func(t *testing.T) {
			ctx := context.Background()
			db, _, _ := sqlmock.New(sqlmock.QueryMatcherOption(sqlmock.QueryMatcherRegexp))

			bucketRepository := new(bucketMocks.MockBucketRepository)
			objectRepository := testScenario.setupMock()
			versionRepository := new(versionMocks.MockVersionRepository)
			permissionRepository := new(permissionMocks.MockPermissionRepository)
			loggerService := setupObjectServiceDependencies()

			svc := objectService.New(
				loggerService,
				objectRepository,
				permissionRepository,
				bucketRepository,
				db,
				versionRepository,
			)

			_, _, err := svc.GetWithVersioningDisabled(ctx, "test", 1)
			if (err != nil) != testScenario.wantErr {
				t.Errorf("GetWithVersioningDisabled() error = %v, wantErr = %v", err, testScenario.wantErr)
			}

			if err != nil && testScenario.err != nil {
				if err.Error() != testScenario.err.Error() {
					t.Errorf("GetWithVersioningDisabled() error = %v, scenarioError = %v", err, testScenario.err)
				}
			}
		})
	}
}

func TestGet(t *testing.T) {
	type args struct {
		title     string
		setupMock func() (objectService.ObjectRepository, objectService.VersionRepository, objectService.BucketRepository)
		wantErr   bool
		err       error
	}
	testScenarios := []args{
		{
			title: "with proper data and with versioning disabled",
			setupMock: func() (objectService.ObjectRepository, objectService.VersionRepository, objectService.BucketRepository) {
				mBucketRepository := new(bucketMocks.MockBucketRepository)
				mBucketRepository.On("IsVersioningEnabled", mock.Anything, mock.Anything).
					Return(false, nil)
				mObjectRepository := new(objectMocks.MockObjectRepository)
				mObjectRepository.On("GetUUIDByID", mock.Anything, mock.Anything, mock.Anything).
					Return("test", nil)
				mObjectRepository.On("GetMetadata", mock.Anything, mock.Anything, mock.Anything).
					Return(model.GetMetadata{ContentType: "text", SizeBytes: 1, ETAG: "test"}, nil)
				mVersionRepository := new(versionMocks.MockVersionRepository)
				return mObjectRepository, mVersionRepository, mBucketRepository
			},
			wantErr: false,
			err:     nil,
		},
		{
			title: "with proper data and with versioning enabled",
			setupMock: func() (objectService.ObjectRepository, objectService.VersionRepository, objectService.BucketRepository) {
				mBucketRepository := new(bucketMocks.MockBucketRepository)
				mBucketRepository.On("IsVersioningEnabled", mock.Anything, mock.Anything).
					Return(true, nil)
				mObjectRepository := new(objectMocks.MockObjectRepository)
				mVersionRepository := new(versionMocks.MockVersionRepository)
				mVersionRepository.On("GetMetadata", mock.Anything, mock.Anything, mock.Anything, mock.Anything).
					Return(model.GetMetadata{ContentType: "text", ETAG: "zaqwewqewq", SizeBytes: 1, IsDeleted: false}, nil)
				mVersionRepository.On("GetUUIDByObjectKey", mock.Anything, mock.Anything, mock.Anything).
					Return("test", nil)
				return mObjectRepository, mVersionRepository, mBucketRepository
			},
			wantErr: false,
			err:     nil,
		},
		{
			title: "IsVersioningEnabled failed",
			setupMock: func() (objectService.ObjectRepository, objectService.VersionRepository, objectService.BucketRepository) {
				mBucketRepository := new(bucketMocks.MockBucketRepository)
				mBucketRepository.On("IsVersioningEnabled", mock.Anything, mock.Anything).
					Return(false, errors.New("failed to perform query"))
				mObjectRepository := new(objectMocks.MockObjectRepository)
				mVersionRepository := new(versionMocks.MockVersionRepository)
				mVersionRepository.On("GetMetadata", mock.Anything, mock.Anything, mock.Anything, mock.Anything).
					Return(model.GetMetadata{ContentType: "text", ETAG: "zaqwewqewq", SizeBytes: 1, IsDeleted: false}, nil)
				mVersionRepository.On("GetUUIDByObjectKey", mock.Anything, mock.Anything, mock.Anything).
					Return("test", nil)
				return mObjectRepository, mVersionRepository, mBucketRepository
			},
			wantErr: true,
			err:     errors.New("failed to perform query"),
		},
	}

	for _, testScenario := range testScenarios {
		t.Run(testScenario.title, func(t *testing.T) {
			ctx := context.Background()
			db, _, _ := sqlmock.New(sqlmock.QueryMatcherOption(sqlmock.QueryMatcherRegexp))

			objectRepository, versionRepository, bucketRepository := testScenario.setupMock()
			permissionRepository := new(permissionMocks.MockPermissionRepository)
			loggerService := setupObjectServiceDependencies()

			svc := objectService.New(
				loggerService,
				objectRepository,
				permissionRepository,
				bucketRepository,
				db,
				versionRepository,
			)

			_, _, err := svc.Get(ctx, 1, 1, "test")
			if (err != nil) != testScenario.wantErr {
				t.Errorf("Get() error = %v, wantErr = %v", err, testScenario.wantErr)
			}

			if err != nil && testScenario.err != nil {
				if err.Error() != testScenario.err.Error() {
					t.Errorf("Get() error = %v, scenarioError = %v", err, testScenario.err)
				}
			}
		})
	}
}
