package service

import (
	"context"
	"database/sql"

	"github.com/google/uuid"
	commonErrors "github.com/slodkiadrianek/MINI-BUCKET/common/errors"
	commonInterfaces "github.com/slodkiadrianek/MINI-BUCKET/common/interfaces"
	dto "github.com/slodkiadrianek/MINI-BUCKET/internal/objects/DTO"
)

type (
	bucketRepository interface {
		Exists(ctx context.Context, bucketID int) (bool, error)
	}
	objectRepository interface {
		Create(ctx context.Context, tx *sql.Tx, file dto.Create) (int, error)
		GetNewVersionNumber(ctx context.Context, tx *sql.Tx, objectID int) (int, error)
		CreateVersion(ctx context.Context, file dto.CreateVersion) error
		Exists(ctx context.Context, tx *sql.Tx, objectID int) (bool, error)
	}
	permissionRepository interface {
		GetPermissionValByUserID(ctx context.Context, bucketID, userID int) (int, error)
	}
)

type ObjectService struct {
	loggerService        commonInterfaces.Logger
	objectRepository     objectRepository
	permissionRepository permissionRepository
	bucketRepository     bucketRepository
	db                   *sql.DB
}

func NewObjectService(loggerService commonInterfaces.Logger, objectRepository objectRepository) *ObjectService {
	return &ObjectService{
		loggerService:    loggerService,
		objectRepository: objectRepository,
	}
}

func (obs *ObjectService) Create(ctx context.Context, objectID, bucketID, userID int, fileInfo dto.IncomingFile) error {
	permission, err := obs.permissionRepository.GetPermissionValByUserID(ctx, bucketID, userID)
	if err != nil {
		return err
	}

	if permission != 2 && permission != 6 && permission != 3 {
		obs.loggerService.Info("user tried to perform operation which is not allowed for him", userID)
		return commonErrors.NewAPIError(403, "you are not allowed to do this action")
	}

	doesBucketExist, err := obs.bucketRepository.Exists(ctx, bucketID)
	if err != nil {
		return err
	}
	if !doesBucketExist {
		return commonErrors.NewAPIError(404, "bucket with provided id does not exist")
	}

	tx, err := obs.db.BeginTx(ctx, nil)
	if err != nil {
		return err
	}
	defer tx.Rollback()

	doesObjectExist, err := obs.objectRepository.Exists(ctx, tx, objectID)
	if err != nil {
		tx.Rollback()
		return err
	}

	object := dto.Create{
		BucketID:    bucketID,
		ObjectKey:   uuid.NewString(),
		ContentType: fileInfo.ContentType,
		SizeBytes:   fileInfo.SizeBytes,
		ETag:        "",
	}
	if !doesObjectExist {
		objectID, err = obs.objectRepository.Create(ctx, tx, object)
	}

	// TODO: upload file to disk

	newVersionNumber, err := obs.objectRepository.GetNewVersionNumber(ctx, tx, objectID)
	if err != nil {
		return err
	}

	newVersionInfo := dto.CreateVersion{
		ObjectID:      objectID,
		VersionNumber: newVersionNumber,
		SizeBytes:     fileInfo.SizeBytes,
		ETag:          "",
		StorageClass:  "",
	}
	err = obs.objectRepository.CreateVersion(ctx, newVersionInfo)
	if err != nil {
		return err
	}

	return nil
}
