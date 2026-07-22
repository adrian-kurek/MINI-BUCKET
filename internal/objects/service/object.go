package service

import (
	"context"
	"database/sql"

	commonInterfaces "github.com/slodkiadrianek/MINI-BUCKET/common/interfaces"
	objectsDTO "github.com/slodkiadrianek/MINI-BUCKET/internal/objects/DTO"
	"github.com/slodkiadrianek/MINI-BUCKET/internal/objects/model"
	versionsDTO "github.com/slodkiadrianek/MINI-BUCKET/internal/versions/DTO"
)

type (
	BucketRepository interface {
		Exists(ctx context.Context, bucketID int) (bool, error)
		GetPrivacyInfo(ctx context.Context, bucketID int) (bool, error)
		IsVersioningEnabled(ctx context.Context, bucketID int) (bool, error)
		UpdateTotalSize(ctx context.Context, bucketID, sizeBytes int) error
	}
	VersionRepository interface {
		GetNewVersionNumber(ctx context.Context, tx *sql.Tx, objectID int) (int, error)
		Create(ctx context.Context, tx *sql.Tx, file versionsDTO.Create) (int, error)
		GetMetadata(ctx context.Context, bucketID int, objectKey string, versionID int) (model.GetMetadata, error)
		CreateDeleteMarker(ctx context.Context, tx *sql.Tx, objectID int) (int, error)
		Delete(ctx context.Context, versionID int) error
		GetUUIDByID(ctx context.Context, versionID int) (string, error)
		GetUUIDByObjectKey(ctx context.Context, bucketID int, objectKey string) (string, error)
		GetUUIDsAndObjectKeysByObjectKeys(ctx context.Context, bucketID int, objectKeys []string) ([]model.ObjectKeyWithUUID, error)
	}
	ObjectRepository interface {
		Create(ctx context.Context, tx *sql.Tx, file objectsDTO.Create) (int, error)
		GetObjectID(ctx context.Context, objectKey string, bucketID int) (bool, int, error)
		UpdateCurrentVersionIDOfObject(ctx context.Context, tx *sql.Tx, objectID, versionID int) error
		GetMetadata(ctx context.Context, bucketID int, objectKey string) (model.GetMetadata, error)
		Update(ctx context.Context, tx *sql.Tx, file objectsDTO.Update) error
		DeleteOne(ctx context.Context, objectKey string) error
		GetUUIDByID(ctx context.Context, objectKey string, bucketID int) (string, error)
		DeleteMany(ctx context.Context, objectKeys []string) error
	}
	PermissionRepository interface {
		GetPermissionValByUserID(ctx context.Context, bucketID, userID int) (int, error)
	}
)

type ObjectService struct {
	loggerService        commonInterfaces.Logger
	objectRepository     ObjectRepository
	permissionRepository PermissionRepository
	bucketRepository     BucketRepository
	versionRepository    VersionRepository
	db                   *sql.DB
}

func New(
	loggerService commonInterfaces.Logger,
	objectRepository ObjectRepository,
	permissionRepository PermissionRepository,
	bucketRepository BucketRepository,
	db *sql.DB,
	versionRepository VersionRepository,
) *ObjectService {
	return &ObjectService{
		loggerService:        loggerService,
		objectRepository:     objectRepository,
		permissionRepository: permissionRepository,
		bucketRepository:     bucketRepository,
		versionRepository:    versionRepository,
		db:                   db,
	}
}
