package service

import (
	"context"
	"errors"
	"strings"
	"testing"
	"time"

	"github.com/DATA-DOG/go-sqlmock"
	"github.com/slodkiadrianek/MINI-BUCKET/internal/objects/DTO"
	bucketMocks "github.com/slodkiadrianek/MINI-BUCKET/test/mocks/bucket"
	objectMocks "github.com/slodkiadrianek/MINI-BUCKET/test/mocks/objects"
	permissionMocks "github.com/slodkiadrianek/MINI-BUCKET/test/mocks/permissions"
	versionMocks "github.com/slodkiadrianek/MINI-BUCKET/test/mocks/versions"
	"github.com/stretchr/testify/mock"
)

func TestCreate(t *testing.T) {
	type args struct {
		title     string
		setupMock func() (permissionRepository, objectRepository, versionRepository, bucketRepository)
		wantErr   bool
		err       error
	}

	testScenarios := []args{
		{
			title: "with proper data and versioning disabled and object does exist",
			setupMock: func() (permissionRepository, objectRepository, versionRepository, bucketRepository) {
				mPermissionRepository := new(permissionMocks.MockPermissionRepository)
				mPermissionRepository.On("GetPermissionValByUserID", mock.Anything, mock.Anything, mock.Anything).Return(7, nil)
				mObjectRepository := new(objectMocks.MockObjectRepository)
				mObjectRepository.On("GetObjectID", mock.Anything, mock.Anything, mock.Anything).Return(true, 1, nil)
				mObjectRepository.On("Update", mock.Anything, mock.Anything, mock.Anything).Return(nil)
				mVersionRepository := new(versionMocks.MockVersionRepository)
				mBucketRepository := new(bucketMocks.MockBucketRepository)
				mBucketRepository.On("Exists", mock.Anything, mock.Anything).Return(true, nil)
				mBucketRepository.On("IsVersioningEnabled", mock.Anything, mock.Anything).Return(false, nil)
				mBucketRepository.On("UpdateTotalSize", mock.Anything, mock.Anything, mock.Anything).Return(nil)
				return mPermissionRepository, mObjectRepository, mVersionRepository, mBucketRepository
			},
			wantErr: false,
			err:     nil,
		},
		{
			title: "failed to create object when versioning disabled",
			setupMock: func() (permissionRepository, objectRepository, versionRepository, bucketRepository) {
				mPermissionRepository := new(permissionMocks.MockPermissionRepository)
				mPermissionRepository.On("GetPermissionValByUserID", mock.Anything, mock.Anything, mock.Anything).Return(7, nil)
				mObjectRepository := new(objectMocks.MockObjectRepository)
				mObjectRepository.On("GetObjectID", mock.Anything, mock.Anything, mock.Anything).Return(false, 0, nil)
				mObjectRepository.On("Create", mock.Anything, mock.Anything, mock.Anything).Return(1, errors.New("failed to perform query"))
				mVersionRepository := new(versionMocks.MockVersionRepository)
				mBucketRepository := new(bucketMocks.MockBucketRepository)
				mBucketRepository.On("Exists", mock.Anything, mock.Anything).Return(true, nil)
				mBucketRepository.On("IsVersioningEnabled", mock.Anything, mock.Anything).Return(false, nil)
				return mPermissionRepository, mObjectRepository, mVersionRepository, mBucketRepository
			},
			wantErr: true,
			err:     errors.New("failed to perform query"),
		},
		{
			title: "failed to update total size of an bucket",
			setupMock: func() (permissionRepository, objectRepository, versionRepository, bucketRepository) {
				mPermissionRepository := new(permissionMocks.MockPermissionRepository)
				mPermissionRepository.On("GetPermissionValByUserID", mock.Anything, mock.Anything, mock.Anything).Return(7, nil)
				mObjectRepository := new(objectMocks.MockObjectRepository)
				mObjectRepository.On("GetObjectID", mock.Anything, mock.Anything, mock.Anything).Return(false, 0, nil)
				mObjectRepository.On("Create", mock.Anything, mock.Anything, mock.Anything).Return(1, nil)
				mObjectRepository.On("UpdateCurrentVersionIDOfObject", mock.Anything, mock.Anything, mock.Anything, mock.Anything).Return(nil)
				mVersionRepository := new(versionMocks.MockVersionRepository)
				mVersionRepository.On("Create", mock.Anything, mock.Anything, mock.Anything).Return(1, nil)
				mBucketRepository := new(bucketMocks.MockBucketRepository)
				mBucketRepository.On("Exists", mock.Anything, mock.Anything).Return(true, nil)
				mBucketRepository.On("IsVersioningEnabled", mock.Anything, mock.Anything).Return(true, nil)
				mBucketRepository.On("UpdateTotalSize", mock.Anything, mock.Anything, mock.Anything).Return(errors.New("failed to perform query"))
				return mPermissionRepository, mObjectRepository, mVersionRepository, mBucketRepository
			},
			wantErr: true,
			err:     errors.New("failed to perform query"),
		},
		{
			title: "failed to update current version id of an object",
			setupMock: func() (permissionRepository, objectRepository, versionRepository, bucketRepository) {
				mPermissionRepository := new(permissionMocks.MockPermissionRepository)
				mPermissionRepository.On("GetPermissionValByUserID", mock.Anything, mock.Anything, mock.Anything).Return(7, nil)
				mObjectRepository := new(objectMocks.MockObjectRepository)
				mObjectRepository.On("GetObjectID", mock.Anything, mock.Anything, mock.Anything).Return(false, 0, nil)
				mObjectRepository.On("Create", mock.Anything, mock.Anything, mock.Anything).Return(1, nil)
				mObjectRepository.On("UpdateCurrentVersionIDOfObject", mock.Anything, mock.Anything, mock.Anything, mock.Anything).Return(errors.New("failed to perform query"))
				mVersionRepository := new(versionMocks.MockVersionRepository)
				mVersionRepository.On("Create", mock.Anything, mock.Anything, mock.Anything).Return(1, nil)
				mBucketRepository := new(bucketMocks.MockBucketRepository)
				mBucketRepository.On("Exists", mock.Anything, mock.Anything).Return(true, nil)
				mBucketRepository.On("IsVersioningEnabled", mock.Anything, mock.Anything).Return(true, nil)
				return mPermissionRepository, mObjectRepository, mVersionRepository, mBucketRepository
			},
			wantErr: true,
			err:     errors.New("failed to perform query"),
		},
		{
			title: "failed to create version",
			setupMock: func() (permissionRepository, objectRepository, versionRepository, bucketRepository) {
				mPermissionRepository := new(permissionMocks.MockPermissionRepository)
				mPermissionRepository.On("GetPermissionValByUserID", mock.Anything, mock.Anything, mock.Anything).Return(7, nil)
				mObjectRepository := new(objectMocks.MockObjectRepository)
				mObjectRepository.On("GetObjectID", mock.Anything, mock.Anything, mock.Anything).Return(false, 0, nil)
				mObjectRepository.On("Create", mock.Anything, mock.Anything, mock.Anything).Return(1, nil)
				mVersionRepository := new(versionMocks.MockVersionRepository)
				mVersionRepository.On("Create", mock.Anything, mock.Anything, mock.Anything).Return(0, errors.New("failed to perform query"))
				mBucketRepository := new(bucketMocks.MockBucketRepository)
				mBucketRepository.On("Exists", mock.Anything, mock.Anything).Return(true, nil)
				mBucketRepository.On("IsVersioningEnabled", mock.Anything, mock.Anything).Return(true, nil)
				return mPermissionRepository, mObjectRepository, mVersionRepository, mBucketRepository
			},
			wantErr: true,
			err:     errors.New("failed to perform query"),
		},
		{
			title: "failed to create object when versioning enabled",
			setupMock: func() (permissionRepository, objectRepository, versionRepository, bucketRepository) {
				mPermissionRepository := new(permissionMocks.MockPermissionRepository)
				mPermissionRepository.On("GetPermissionValByUserID", mock.Anything, mock.Anything, mock.Anything).Return(7, nil)
				mObjectRepository := new(objectMocks.MockObjectRepository)
				mObjectRepository.On("GetObjectID", mock.Anything, mock.Anything, mock.Anything).Return(false, 0, nil)
				mObjectRepository.On("Create", mock.Anything, mock.Anything, mock.Anything).Return(1, errors.New("failed to perform query"))
				mVersionRepository := new(versionMocks.MockVersionRepository)
				mBucketRepository := new(bucketMocks.MockBucketRepository)
				mBucketRepository.On("Exists", mock.Anything, mock.Anything).Return(true, nil)
				mBucketRepository.On("IsVersioningEnabled", mock.Anything, mock.Anything).Return(true, nil)
				return mPermissionRepository, mObjectRepository, mVersionRepository, mBucketRepository
			},
			wantErr: true,
			err:     errors.New("failed to perform query"),
		},
		{
			title: "failed to update object ",
			setupMock: func() (permissionRepository, objectRepository, versionRepository, bucketRepository) {
				mPermissionRepository := new(permissionMocks.MockPermissionRepository)
				mPermissionRepository.On("GetPermissionValByUserID", mock.Anything, mock.Anything, mock.Anything).Return(7, nil)
				mObjectRepository := new(objectMocks.MockObjectRepository)
				mObjectRepository.On("GetObjectID", mock.Anything, mock.Anything, mock.Anything).Return(true, 1, nil)
				mObjectRepository.On("Update", mock.Anything, mock.Anything, mock.Anything).Return(errors.New("failed to perform query"))
				mVersionRepository := new(versionMocks.MockVersionRepository)
				mBucketRepository := new(bucketMocks.MockBucketRepository)
				mBucketRepository.On("Exists", mock.Anything, mock.Anything).Return(true, nil)
				mBucketRepository.On("IsVersioningEnabled", mock.Anything, mock.Anything).Return(false, nil)
				return mPermissionRepository, mObjectRepository, mVersionRepository, mBucketRepository
			},
			wantErr: true,
			err:     errors.New("failed to perform query"),
		},
		{
			title: "failed to check permissions",
			setupMock: func() (permissionRepository, objectRepository, versionRepository, bucketRepository) {
				mPermissionRepository := new(permissionMocks.MockPermissionRepository)
				mPermissionRepository.On("GetPermissionValByUserID", mock.Anything, mock.Anything, mock.Anything).Return(0, errors.New("failed to perform query"))
				mObjectRepository := new(objectMocks.MockObjectRepository)
				mVersionRepository := new(versionMocks.MockVersionRepository)
				mBucketRepository := new(bucketMocks.MockBucketRepository)
				return mPermissionRepository, mObjectRepository, mVersionRepository, mBucketRepository
			},
			wantErr: true,
			err:     errors.New("failed to perform query"),
		},
		{
			title: "failed to check does bucket exists",
			setupMock: func() (permissionRepository, objectRepository, versionRepository, bucketRepository) {
				mPermissionRepository := new(permissionMocks.MockPermissionRepository)
				mPermissionRepository.On("GetPermissionValByUserID", mock.Anything, mock.Anything, mock.Anything).Return(7, nil)
				mObjectRepository := new(objectMocks.MockObjectRepository)
				mVersionRepository := new(versionMocks.MockVersionRepository)
				mBucketRepository := new(bucketMocks.MockBucketRepository)
				mBucketRepository.On("Exists", mock.Anything, mock.Anything).Return(false, errors.New("failed to perform the query"))
				return mPermissionRepository, mObjectRepository, mVersionRepository, mBucketRepository
			},
			wantErr: true,
			err:     errors.New("failed to perform the query"),
		},
		{
			title: "failed to check is versioning enabled",
			setupMock: func() (permissionRepository, objectRepository, versionRepository, bucketRepository) {
				mPermissionRepository := new(permissionMocks.MockPermissionRepository)
				mPermissionRepository.On("GetPermissionValByUserID", mock.Anything, mock.Anything, mock.Anything).Return(7, nil)
				mObjectRepository := new(objectMocks.MockObjectRepository)
				mVersionRepository := new(versionMocks.MockVersionRepository)
				mBucketRepository := new(bucketMocks.MockBucketRepository)
				mBucketRepository.On("Exists", mock.Anything, mock.Anything).Return(true, nil)
				mBucketRepository.On("IsVersioningEnabled", mock.Anything, mock.Anything).Return(false, errors.New("failed to perform the query"))
				return mPermissionRepository, mObjectRepository, mVersionRepository, mBucketRepository
			},
			wantErr: true,
			err:     errors.New("failed to perform the query"),
		},
		{
			title: "failed to get object id",
			setupMock: func() (permissionRepository, objectRepository, versionRepository, bucketRepository) {
				mPermissionRepository := new(permissionMocks.MockPermissionRepository)
				mPermissionRepository.On("GetPermissionValByUserID", mock.Anything, mock.Anything, mock.Anything).Return(7, nil)
				mObjectRepository := new(objectMocks.MockObjectRepository)
				mObjectRepository.On("GetObjectID", mock.Anything, mock.Anything, mock.Anything).Return(false, 0, errors.New("failed to perform the query"))
				mVersionRepository := new(versionMocks.MockVersionRepository)
				mBucketRepository := new(bucketMocks.MockBucketRepository)
				mBucketRepository.On("Exists", mock.Anything, mock.Anything).Return(true, nil)
				mBucketRepository.On("IsVersioningEnabled", mock.Anything, mock.Anything).Return(true, nil)
				return mPermissionRepository, mObjectRepository, mVersionRepository, mBucketRepository
			},
			wantErr: true,
			err:     errors.New("failed to perform the query"),
		},
	}

	for _, testScenario := range testScenarios {
		t.Run(testScenario.title, func(t *testing.T) {
			ctx, cancel := context.WithTimeout(context.Background(), 2*time.Second)
			defer cancel()

			db, mockSQl, _ := sqlmock.New(sqlmock.QueryMatcherOption(sqlmock.QueryMatcherRegexp))
			mockSQl.ExpectBegin()
			mockSQl.ExpectCommit()

			permissionRepository, objectRepository, versionRepository, bucketRepository := testScenario.setupMock()
			loggerService := setupObjectServiceDependencies()
			objectService := NewObjectService(loggerService, objectRepository, permissionRepository, bucketRepository, db, versionRepository)

			fileInfo := DTO.IncomingFile{
				File:        strings.NewReader("test file content"),
				ContentType: "text/plain",
				SizeBytes:   18,
			}

			err := objectService.Upload(ctx, 11, 1, fileInfo)
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
