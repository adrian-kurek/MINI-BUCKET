package service_test

import (
	"context"
	"database/sql"
	"errors"
	"os"
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

func TestCheckExecutePermissions(t *testing.T) {
	type args struct {
		title string
		setupMock func () ( objectService.PermissionRepository)
		wantErr bool 
		err error
	}

	testScenarios := []args{
		{
			title: "with proper data",
			setupMock: func() (objectService.PermissionRepository) {
				mPermissionRepository := new(permissionMocks.MockPermissionRepository)
				mPermissionRepository.On("GetPermissionValByUserID",mock.Anything,mock.Anything,mock.Anything).Return(7,nil)
				return mPermissionRepository
			},
			wantErr: false,
			err: nil,
		},
		{
			title: "user is not allowed to perform an action",
			setupMock: func() ( objectService.PermissionRepository) {
				mPermissionRepository := new(permissionMocks.MockPermissionRepository)
				mPermissionRepository.On("GetPermissionValByUserID",mock.Anything,mock.Anything,mock.Anything).Return(5,nil)
				return mPermissionRepository
			},
			wantErr: true,
			err: errors.New("api error: you are not allowed to do this action"),
		},
		{
			title: "GetPermissionValByUserID failed",
			setupMock: func() ( objectService.PermissionRepository) {
				mPermissionRepository := new(permissionMocks.MockPermissionRepository)
				mPermissionRepository.On("GetPermissionValByUserID",mock.Anything,mock.Anything,mock.Anything).Return(0,errors.New("failed to perform query"))
				return mPermissionRepository
			},
			wantErr: true,
			err: errors.New("failed to perform query"),
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

			err := svc.CheckExecutePermissions(ctx, 1, 1)
			if (err != nil) != testScenario.wantErr {
				t.Errorf("CheckExecutePermissions() error = %v, wantErr = %v", err, testScenario.wantErr)
			}

			if err != nil && testScenario.err != nil {
				if err.Error() != testScenario.err.Error() {
					t.Errorf("CheckExecutePermissions() error = %v, scenarioError = %v", err, testScenario.err)
				}
			}
		})
	}
}

func TestCreateDeleteMarker(t *testing.T) {
	type args struct {
		title string
		setupMock func () (objectService.ObjectRepository, objectService.VersionRepository,*sql.DB)
		wantErr bool 
		err error
	}

	testScenarios := []args{
		{
			title: "with proper data",
			setupMock: func() (objectService.ObjectRepository, objectService.VersionRepository,*sql.DB) {
				mObjectRepository := new(objectMocks.MockObjectRepository)
				mObjectRepository.On("GetObjectID",mock.Anything,mock.Anything,mock.Anything).Return(true,1,nil)
				mObjectRepository.On("UpdateCurrentVersionIDOfObject", mock.Anything,mock.Anything,mock.Anything,mock.Anything).
				Return(nil)
				mVersionRepository := new(versionMocks.MockVersionRepository)
				mVersionRepository.On("CreateDeleteMarker",mock.Anything,mock.Anything,mock.Anything).Return(1,nil)
				db,mock,_ := sqlmock.New()
				mock.ExpectBegin()
				mock.ExpectCommit()
				return mObjectRepository, mVersionRepository,db
			},
			wantErr: false,
			err: nil,
		},
		{
			title: "object does not exists",
			setupMock: func() (objectService.ObjectRepository, objectService.VersionRepository,*sql.DB) {
				mObjectRepository := new(objectMocks.MockObjectRepository)
				mObjectRepository.On("GetObjectID",mock.Anything,mock.Anything,mock.Anything).Return(false,0,nil)
				mVersionRepository := new(versionMocks.MockVersionRepository)
				db,mock,_ := sqlmock.New()
				mock.ExpectBegin()
				mock.ExpectCommit()
				return mObjectRepository, mVersionRepository,db
			},
			wantErr: true,
			err: errors.New("api error: failed to find object with provided id"),
		},
		{
			title: "GetObjectID failed",
			setupMock: func() (objectService.ObjectRepository, objectService.VersionRepository,*sql.DB) {
				mObjectRepository := new(objectMocks.MockObjectRepository)
				mObjectRepository.On("GetObjectID",mock.Anything,mock.Anything,mock.Anything).
				Return(true,0,errors.New("failed to perform and query"))
				mVersionRepository := new(versionMocks.MockVersionRepository)
				db,mock,_ := sqlmock.New()
				mock.ExpectBegin()
				mock.ExpectCommit()
				return mObjectRepository, mVersionRepository,db
			},
			wantErr: true,
			err: errors.New("failed to perform and query"),
		},
		{
			title: "CreateDeleteMarker failed",
			setupMock: func() (objectService.ObjectRepository, objectService.VersionRepository,*sql.DB) {
				mObjectRepository := new(objectMocks.MockObjectRepository)
				mObjectRepository.On("GetObjectID",mock.Anything,mock.Anything,mock.Anything).Return(true,1,nil)
				mVersionRepository := new(versionMocks.MockVersionRepository)
				mVersionRepository.On("CreateDeleteMarker",mock.Anything,mock.Anything,mock.Anything).
				Return(1,errors.New("failed to perform query"))
				db,mock,_ := sqlmock.New()
				mock.ExpectBegin()
				mock.ExpectRollback()
				return mObjectRepository, mVersionRepository,db
			},
			wantErr: true,
			err: errors.New("failed to perform query"),
		},
		{
			title: "UpdateCurrentVersionIDOfObject failed",
			setupMock: func() (objectService.ObjectRepository, objectService.VersionRepository,*sql.DB) {
				mObjectRepository := new(objectMocks.MockObjectRepository)
				mObjectRepository.On("GetObjectID",mock.Anything,mock.Anything,mock.Anything).Return(true,1,nil)
				mObjectRepository.On("UpdateCurrentVersionIDOfObject", mock.Anything,mock.Anything,mock.Anything,mock.Anything).
				Return(errors.New("failed to perform query"))
				mVersionRepository := new(versionMocks.MockVersionRepository)
				mVersionRepository.On("CreateDeleteMarker",mock.Anything,mock.Anything,mock.Anything).Return(1,nil)
				db,mock,_ := sqlmock.New()
				mock.ExpectBegin()
				mock.ExpectRollback()
				return mObjectRepository, mVersionRepository,db
			},
			wantErr: true,
			err: errors.New("failed to perform query"),
		},
	}

	for _, testScenario := range testScenarios {
		t.Run(testScenario.title, func(t *testing.T) {
			ctx, cancel := context.WithTimeout(context.Background(), 2*time.Second)
			defer cancel()
			db, _, _ := sqlmock.New(sqlmock.QueryMatcherOption(sqlmock.QueryMatcherRegexp))

			bucketRepository := new(bucketMocks.MockBucketRepository)
			permissionRepository := new(permissionMocks.MockPermissionRepository) 
			objectRepository, versionRepository,db := testScenario.setupMock()
			loggerService := setupObjectServiceDependencies()

			svc := objectService.New(
				loggerService,
				objectRepository,
				permissionRepository,
				bucketRepository,
				db,
				versionRepository,
			)

			err := svc.CreateDeleteMarker(ctx, "test", 1)
			if (err != nil) != testScenario.wantErr {
				t.Errorf("CreateDeleteMarker() error = %v, wantErr = %v", err, testScenario.wantErr)
			}

			if err != nil && testScenario.err != nil {
				if err.Error() != testScenario.err.Error() {
					t.Errorf("CreateDeleteMarker() error = %v, scenarioError = %v", err, testScenario.err)
				}
			}
		})
	}
}

func TestDeleteObjectVersionByID(t *testing.T) {
	type args struct {
		title string
		createFile bool
		setupMock func () ( objectService.VersionRepository,*sql.DB)
		wantErr bool 
		err error
	}

	testScenarios := []args{
		{
			title: "with proper data",
			createFile: true,
			setupMock: func() ( objectService.VersionRepository,*sql.DB) {
				mVersionRepository := new(versionMocks.MockVersionRepository)
				mVersionRepository.On("GetUUIDByID",mock.Anything,mock.Anything).Return("test",nil)
				mVersionRepository.On("Delete",mock.Anything,mock.Anything).Return(nil)
				db,mock,_ := sqlmock.New()
				mock.ExpectBegin()
				mock.ExpectCommit()
				return  mVersionRepository,db
			},
			wantErr: false,
			err: nil,
		},
		{
			title: "GetUUIDByID failed",
			createFile: false,
			setupMock: func() ( objectService.VersionRepository,*sql.DB) {
				mVersionRepository := new(versionMocks.MockVersionRepository)
				mVersionRepository.On("GetUUIDByID",mock.Anything,mock.Anything).
				Return("",errors.New("failed to perform query"))
				db,_,_ := sqlmock.New()
				return  mVersionRepository,db
			},
			wantErr: true,
			err: errors.New("failed to perform query"),
		},
		{
			title: "Delete failed",
			createFile: false,
			setupMock: func() ( objectService.VersionRepository,*sql.DB) {
				mVersionRepository := new(versionMocks.MockVersionRepository)
				mVersionRepository.On("GetUUIDByID",mock.Anything,mock.Anything).Return("test",nil)
				mVersionRepository.On("Delete",mock.Anything,mock.Anything).Return(errors.New("failed to perform query"))
				db,_,_ := sqlmock.New()
				return  mVersionRepository,db
			},
			wantErr: true,
			err: errors.New("failed to perform query"),
		},
		{
			title: "failed to delete the file",
			createFile: false,
			setupMock: func() ( objectService.VersionRepository,*sql.DB) {
				mVersionRepository := new(versionMocks.MockVersionRepository)
				mVersionRepository.On("GetUUIDByID",mock.Anything,mock.Anything).Return("test",nil)
				mVersionRepository.On("Delete",mock.Anything,mock.Anything).Return(nil)
				db,_,_ := sqlmock.New()
				return  mVersionRepository,db
			},
			wantErr: true,
			err: errors.New("remove ./uploads/1/test-test: no such file or directory"),
		},
	}

	for _, testScenario := range testScenarios {
		t.Run(testScenario.title, func(t *testing.T) {
			ctx, cancel := context.WithTimeout(context.Background(), 2*time.Second)
			defer cancel()
			db, _, _ := sqlmock.New(sqlmock.QueryMatcherOption(sqlmock.QueryMatcherRegexp))

			bucketRepository := new(bucketMocks.MockBucketRepository)
			permissionRepository := new(permissionMocks.MockPermissionRepository) 
			objectRepository := new(objectMocks.MockObjectRepository)
			versionRepository,db := testScenario.setupMock()
			loggerService := setupObjectServiceDependencies()

			if testScenario.createFile {
				if err := os.MkdirAll("./uploads/1", 0o755); err != nil {
						panic(err)
				}
				f, err := os.Create("./uploads/1/test-test")
				if err != nil {
						panic(err)
				}
				defer f.Close()
			}

			svc := objectService.New(
				loggerService,
				objectRepository,
				permissionRepository,
				bucketRepository,
				db,
				versionRepository,
			)

			err := svc.DeleteObjectVersionByID(ctx, "test", 1,1)
			if (err != nil) != testScenario.wantErr {
				t.Errorf("DeleteObjectVersionByID() error = %v, wantErr = %v", err, testScenario.wantErr)
			}

			if err != nil && testScenario.err != nil {
				if err.Error() != testScenario.err.Error() {
					t.Errorf("DeleteObjectVersionByID() error = %v, scenarioError = %v", err, testScenario.err)
				}
			}
		})
	}
}

func TestDeleteObject(t *testing.T) {
	type args struct {
		title string
		createFile bool
		setupMock func () ( objectService.ObjectRepository,*sql.DB)
		wantErr bool 
		err error
	}

	testScenarios := []args{
		{
			title: "with proper data",
			createFile: true,
			setupMock: func() ( objectService.ObjectRepository,*sql.DB) {
				mObjectRepository := new(objectMocks.MockObjectRepository)
				mObjectRepository.On("GetUUIDByID",mock.Anything,mock.Anything,mock.Anything).Return("test",nil)
				mObjectRepository.On("DeleteOne",mock.Anything,mock.Anything).Return(nil)
				db,_,_ := sqlmock.New()
				return  mObjectRepository,db
			},
			wantErr: false,
			err: nil,
		},
		{
			title: "GetUUIDByID failed",
			createFile: false,
			setupMock: func() ( objectService.ObjectRepository,*sql.DB) {
				mObjectRepository := new(objectMocks.MockObjectRepository)
				mObjectRepository.On("GetUUIDByID",mock.Anything,mock.Anything,mock.Anything).Return("",errors.New("failed to perform query"))
				db,_,_ := sqlmock.New()
				return  mObjectRepository,db
			},
			wantErr: true,
			err: errors.New("failed to perform query"),
		},
		{
			title: "with proper data",
			createFile: false,
			setupMock: func() ( objectService.ObjectRepository,*sql.DB) {
				mObjectRepository := new(objectMocks.MockObjectRepository)
				mObjectRepository.On("GetUUIDByID",mock.Anything,mock.Anything,mock.Anything).Return("test",nil)
				mObjectRepository.On("DeleteOne",mock.Anything,mock.Anything).Return(errors.New("failed to perform query"))
				db,_,_ := sqlmock.New()
				return  mObjectRepository,db
			},
			wantErr: true,
			err: errors.New("failed to perform query"),
		},
		{
			title: "failed to delete the file",
			createFile: false,
			setupMock: func() ( objectService.ObjectRepository,*sql.DB) {
				mObjectRepository := new(objectMocks.MockObjectRepository)
				mObjectRepository.On("GetUUIDByID",mock.Anything,mock.Anything,mock.Anything).Return("test",nil)
				mObjectRepository.On("DeleteOne",mock.Anything,mock.Anything).Return(nil)
				db,_,_ := sqlmock.New()
				return  mObjectRepository,db
			},
			wantErr: true,
			err: errors.New("remove ./uploads/1/test-test: no such file or directory"),
		},
	}

	for _, testScenario := range testScenarios {
		t.Run(testScenario.title, func(t *testing.T) {
			ctx, cancel := context.WithTimeout(context.Background(), 2*time.Second)
			defer cancel()
			db, _, _ := sqlmock.New(sqlmock.QueryMatcherOption(sqlmock.QueryMatcherRegexp))

			bucketRepository := new(bucketMocks.MockBucketRepository)
			permissionRepository := new(permissionMocks.MockPermissionRepository) 
			versionRepository := new(versionMocks.MockVersionRepository)
			objectRepository,db := testScenario.setupMock()
			loggerService := setupObjectServiceDependencies()

			if testScenario.createFile {
				if err := os.MkdirAll("./uploads/1", 0o755); err != nil {
						panic(err)
				}
				f, err := os.Create("./uploads/1/test-test")
				if err != nil {
						panic(err)
				}
				defer f.Close()
			}

			svc := objectService.New(
				loggerService,
				objectRepository,
				permissionRepository,
				bucketRepository,
				db,
				versionRepository,
			)

			err := svc.DeleteObject(ctx, "test", 1)
			if (err != nil) != testScenario.wantErr {
				t.Errorf("DeleteObject() error = %v, wantErr = %v", err, testScenario.wantErr)
			}

			if err != nil && testScenario.err != nil {
				if err.Error() != testScenario.err.Error() {
					t.Errorf("DeleteObject() error = %v, scenarioError = %v", err, testScenario.err)
				}
			}
		})
	}
}

func TestDelete(t *testing.T) {
	type args struct {
		title string
		createFile bool
		versionID int
		setupMock func () ( objectService.ObjectRepository,objectService.BucketRepository, objectService.VersionRepository, objectService.PermissionRepository,*sql.DB)
		wantErr bool 
		err error
	}

	testScenarios := []args{
		{
			title: "with proper data , with versioning disabled",
			createFile: true,
			setupMock: func() ( objectService.ObjectRepository,objectService.BucketRepository,objectService.VersionRepository,objectService.PermissionRepository,*sql.DB) {
				mObjectRepository := new(objectMocks.MockObjectRepository)
				mVersionRepository := new(versionMocks.MockVersionRepository)
				mBucketRepository := new(bucketMocks.MockBucketRepository)
				mBucketRepository.On("Exists", mock.Anything, mock.Anything).Return(true, nil)
				mBucketRepository.On("IsVersioningEnabled",mock.Anything,mock.Anything).Return(false,nil)
				mPermissionRepository := new(permissionMocks.MockPermissionRepository)
				mPermissionRepository.On("GetPermissionValByUserID",mock.Anything,mock.Anything,mock.Anything).Return(7,nil)
				mObjectRepository.On("GetUUIDByID",mock.Anything,mock.Anything,mock.Anything).Return("test",nil)
				mObjectRepository.On("DeleteOne",mock.Anything,mock.Anything).Return(nil)
				db,_,_ := sqlmock.New()
				return  mObjectRepository,mBucketRepository,mVersionRepository,mPermissionRepository,db
			},
			wantErr: false,
			err: nil,
		},
		{
			title: "with proper data, with versioning enabled, and with versionID",
			createFile: true,
			versionID: 1,
			setupMock: func() ( objectService.ObjectRepository,objectService.BucketRepository,objectService.VersionRepository,objectService.PermissionRepository,*sql.DB) {
				mObjectRepository := new(objectMocks.MockObjectRepository)
				mVersionRepository := new(versionMocks.MockVersionRepository)
				mVersionRepository.On("GetUUIDByID",mock.Anything,mock.Anything).Return("test",nil)
				mVersionRepository.On("Delete",mock.Anything,mock.Anything).Return(nil)
				mBucketRepository := new(bucketMocks.MockBucketRepository)
				mBucketRepository.On("Exists", mock.Anything, mock.Anything).Return(true, nil)
				mBucketRepository.On("IsVersioningEnabled",mock.Anything,mock.Anything).Return(true,nil)
				mPermissionRepository := new(permissionMocks.MockPermissionRepository)
				mPermissionRepository.On("GetPermissionValByUserID",mock.Anything,mock.Anything,mock.Anything).Return(7,nil)
				db,_,_ := sqlmock.New()
				return  mObjectRepository,mBucketRepository,mVersionRepository,mPermissionRepository,db
			},
			wantErr: false,
			err: nil,
		},
		{
			title: "with proper data, with versioning enabled, and without versionID",
			createFile: true,
			versionID: 0,
			setupMock: func() ( objectService.ObjectRepository,objectService.BucketRepository,objectService.VersionRepository,objectService.PermissionRepository,*sql.DB) {
				mObjectRepository := new(objectMocks.MockObjectRepository)
				mObjectRepository.On("GetObjectID",mock.Anything,mock.Anything,mock.Anything).Return(true,1,nil)
				mObjectRepository.On("UpdateCurrentVersionIDOfObject", mock.Anything,mock.Anything,mock.Anything,mock.Anything).
				Return(nil)
				mVersionRepository := new(versionMocks.MockVersionRepository)
				mVersionRepository.On("CreateDeleteMarker",mock.Anything,mock.Anything,mock.Anything).Return(1,nil)
				mBucketRepository := new(bucketMocks.MockBucketRepository)
				mBucketRepository.On("Exists", mock.Anything, mock.Anything).Return(true, nil)
				mBucketRepository.On("IsVersioningEnabled",mock.Anything,mock.Anything).Return(true,nil)
				mPermissionRepository := new(permissionMocks.MockPermissionRepository)
				mPermissionRepository.On("GetPermissionValByUserID",mock.Anything,mock.Anything,mock.Anything).Return(7,nil)
				db,mock,_ := sqlmock.New()
				mock.ExpectBegin()
				mock.ExpectCommit()
				return  mObjectRepository,mBucketRepository,mVersionRepository,mPermissionRepository,db
			},
			wantErr: false,
			err: nil,
		},
		{
			title: "CheckExecutePermissions failed",
			createFile: false,
			setupMock: func() ( objectService.ObjectRepository,objectService.BucketRepository,objectService.VersionRepository,objectService.PermissionRepository,*sql.DB) {
				mObjectRepository := new(objectMocks.MockObjectRepository)
				mVersionRepository := new(versionMocks.MockVersionRepository)
				mBucketRepository := new(bucketMocks.MockBucketRepository)
				mPermissionRepository := new(permissionMocks.MockPermissionRepository)
				mPermissionRepository.On("GetPermissionValByUserID",mock.Anything,mock.Anything,mock.Anything).Return(7,errors.New("failed to perform query"))
				db,_,_ := sqlmock.New()
				return  mObjectRepository,mBucketRepository,mVersionRepository,mPermissionRepository,db
			},
			wantErr: true,
			err: errors.New("failed to perform query"),
		},
		{
			title: "CheckDoesBucketExist failed",
			createFile: false,
			setupMock: func() ( objectService.ObjectRepository,objectService.BucketRepository,objectService.VersionRepository,objectService.PermissionRepository,*sql.DB) {
				mObjectRepository := new(objectMocks.MockObjectRepository)
				mVersionRepository := new(versionMocks.MockVersionRepository)
				mBucketRepository := new(bucketMocks.MockBucketRepository)
				mBucketRepository.On("Exists", mock.Anything, mock.Anything).Return(false, errors.New("failed to perform query"))
				mPermissionRepository := new(permissionMocks.MockPermissionRepository)
				mPermissionRepository.On("GetPermissionValByUserID",mock.Anything,mock.Anything,mock.Anything).Return(7,nil)
				db,_,_ := sqlmock.New()
				return  mObjectRepository,mBucketRepository,mVersionRepository,mPermissionRepository,db
			},
			wantErr: true,
			err: errors.New("failed to perform query"),
		},
		{
			title: "IsVersioningEnabled failed",
			createFile: false,
			setupMock: func() ( objectService.ObjectRepository,objectService.BucketRepository,objectService.VersionRepository,objectService.PermissionRepository,*sql.DB) {
				mObjectRepository := new(objectMocks.MockObjectRepository)
				mVersionRepository := new(versionMocks.MockVersionRepository)
				mBucketRepository := new(bucketMocks.MockBucketRepository)
				mBucketRepository.On("Exists", mock.Anything, mock.Anything).Return(true, nil)
				mBucketRepository.On("IsVersioningEnabled",mock.Anything,mock.Anything).Return(false,errors.New("failed to perform query"))
				mPermissionRepository := new(permissionMocks.MockPermissionRepository)
				mPermissionRepository.On("GetPermissionValByUserID",mock.Anything,mock.Anything,mock.Anything).Return(7,nil)
				db,_,_ := sqlmock.New()
				return  mObjectRepository,mBucketRepository,mVersionRepository,mPermissionRepository,db
			},
			wantErr: true,
			err: errors.New("failed to perform query"),
		},
	}

	for _, testScenario := range testScenarios {
		t.Run(testScenario.title, func(t *testing.T) {
			ctx, cancel := context.WithTimeout(context.Background(), 2*time.Second)
			defer cancel()
			db, _, _ := sqlmock.New(sqlmock.QueryMatcherOption(sqlmock.QueryMatcherRegexp))

			objectRepository,bucketRepository,versionRepository,permissionRepository,db := testScenario.setupMock()
			loggerService := setupObjectServiceDependencies()

			if testScenario.createFile {
				if err := os.MkdirAll("./uploads/1", 0o755); err != nil {
						panic(err)
				}
				f, err := os.Create("./uploads/1/test-test")
				if err != nil {
						panic(err)
				}
				defer f.Close()
			}

			svc := objectService.New(
				loggerService,
				objectRepository,
				permissionRepository,
				bucketRepository,
				db,
				versionRepository,
			)

			err := svc.Delete(ctx,  1,1,"test",testScenario.versionID)
			if (err != nil) != testScenario.wantErr {
				t.Errorf("Delete() error = %v, wantErr = %v", err, testScenario.wantErr)
			}

			if err != nil && testScenario.err != nil {
				if err.Error() != testScenario.err.Error() {
					t.Errorf("Delete() error = %v, scenarioError = %v", err, testScenario.err)
				}
			}
		})
	}
}
