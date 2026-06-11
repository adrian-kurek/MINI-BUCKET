package service

import (
	"context"
	"database/sql"
	"io"
	"os"
	"path/filepath"
	"strconv"

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
		CreateVersion(ctx context.Context, tx *sql.Tx, file dto.CreateVersion) (int, error)
		GetObjectKey(ctx context.Context, tx *sql.Tx, objectID int) (bool, string, error)
		UpdateCurrentVersionIDOfObject(ctx context.Context, tx *sql.Tx, objectID, versionID int) error
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

func NewObjectService(loggerService commonInterfaces.Logger, objectRepository objectRepository, permissionRepository permissionRepository, bucketRepository bucketRepository, db *sql.DB) *ObjectService {
	return &ObjectService{
		loggerService:        loggerService,
		objectRepository:     objectRepository,
		permissionRepository: permissionRepository,
		bucketRepository:     bucketRepository,
		db:                   db,
	}
}

func (obs *ObjectService) Create(ctx context.Context, objectID, bucketID, userID int, fileInfo dto.IncomingFile) error {
	permission, err := obs.permissionRepository.GetPermissionValByUserID(ctx, bucketID, userID)
	if err != nil {
		return err
	}

	if permission != 2 && permission != 6 && permission != 3 && permission != 7 {
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

	doesObjectExist, objectKey, err := obs.objectRepository.GetObjectKey(ctx, tx, objectID)
	if err != nil {
		return err
	}

	if !doesObjectExist {
		object := dto.Create{
			BucketID:    bucketID,
			ObjectKey:   uuid.NewString(),
			ContentType: fileInfo.ContentType,
			SizeBytes:   fileInfo.SizeBytes,
			ETag:        "",
		}
		objectKey = object.ObjectKey
		objectID, err = obs.objectRepository.Create(ctx, tx, object)
		if err != nil {
			return err
		}
	}

	newVersionNumber, err := obs.objectRepository.GetNewVersionNumber(ctx, tx, objectID)
	if err != nil {
		return err
	}

	uploadDir := "./uploads/" + strconv.Itoa(bucketID)
	if err := os.MkdirAll(uploadDir, 0o755); err != nil {
		return err
	}
	destPath := filepath.Join(uploadDir, objectKey+"-"+strconv.Itoa(newVersionNumber))
	destFile, err := os.Create(destPath)
	if err != nil {
		return err
	}
	defer destFile.Close()

	if _, err := io.Copy(destFile, fileInfo.File); err != nil {
		destFile.Close()
		os.Remove(destPath)
		return err
	}

	newVersionInfo := dto.CreateVersion{
		ObjectID:      objectID,
		VersionNumber: newVersionNumber,
		SizeBytes:     fileInfo.SizeBytes,
		ETag:          "",
		StorageClass:  "",
	}
	newVersionID, err := obs.objectRepository.CreateVersion(ctx, tx, newVersionInfo)
	if err != nil {
		os.Remove(destPath)
		return err
	}

	err = obs.objectRepository.UpdateCurrentVersionIDOfObject(ctx, tx, objectID, newVersionID)
	if err != nil {
		os.Remove(destPath)
		return err
	}

	if err := tx.Commit(); err != nil {
		os.Remove(destPath)
		return err
	}
	return nil
}
