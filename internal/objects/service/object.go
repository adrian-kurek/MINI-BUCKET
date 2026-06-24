package service

import (
	"context"
	"crypto/md5"
	"database/sql"
	"encoding/hex"
	"io"
	"os"
	"path/filepath"
	"strconv"

	"github.com/google/uuid"
	commonErrors "github.com/slodkiadrianek/MINI-BUCKET/common/errors"
	commonInterfaces "github.com/slodkiadrianek/MINI-BUCKET/common/interfaces"
	DTO "github.com/slodkiadrianek/MINI-BUCKET/internal/objects/DTO"
	objectsDTO "github.com/slodkiadrianek/MINI-BUCKET/internal/objects/DTO"
	"github.com/slodkiadrianek/MINI-BUCKET/internal/objects/model"
	versionsDTO "github.com/slodkiadrianek/MINI-BUCKET/internal/versions/DTO"
)

type (
	bucketRepository interface {
		Exists(ctx context.Context, bucketID int) (bool, error)
		GetPrivacyInfo(ctx context.Context, bucketID int) (bool, error)
	}
	versionRepository interface {
		GetNewVersionNumber(ctx context.Context, tx *sql.Tx, objectID int) (int, error)
		Create(ctx context.Context, tx *sql.Tx, file versionsDTO.Create) (int, error)
	}
	objectRepository interface {
		Create(ctx context.Context, tx *sql.Tx, file objectsDTO.Create) (int, error)
		GetObjectKey(ctx context.Context, tx *sql.Tx, objectID int) (bool, string, error)
		UpdateCurrentVersionIDOfObject(ctx context.Context, tx *sql.Tx, objectID, versionID int) error
		GetMetadata(ctx context.Context, bucketID int, objectKey string, versionNumber int) (model.GetMetadata, error)
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
	versionRepository    versionRepository
	db                   *sql.DB
}

func NewObjectService(loggerService commonInterfaces.Logger, objectRepository objectRepository, permissionRepository permissionRepository, bucketRepository bucketRepository, db *sql.DB, versionRepository versionRepository) *ObjectService {
	return &ObjectService{
		loggerService:        loggerService,
		objectRepository:     objectRepository,
		permissionRepository: permissionRepository,
		bucketRepository:     bucketRepository,
		versionRepository:    versionRepository,
		db:                   db,
	}
}

func (obs *ObjectService) checkPermissions(ctx context.Context, bucketID, userID int) error {
	permission, err := obs.permissionRepository.GetPermissionValByUserID(ctx, bucketID, userID)
	if err != nil {
		return err
	}
	if permission != 2 && permission != 6 && permission != 3 && permission != 7 {
		obs.loggerService.Info("user tried to perform operation which is not allowed for him", userID)
		return commonErrors.NewAPIError(403, "you are not allowed to do this action")
	}
	return nil
}

func (obs *ObjectService) checkDoesBucketExist(ctx context.Context, bucketID int) error {
	doesBucketExist, err := obs.bucketRepository.Exists(ctx, bucketID)
	if err != nil {
		return err
	}
	if !doesBucketExist {
		return commonErrors.NewAPIError(404, "bucket with provided id does not exist")
	}
	return nil
}

func (obs *ObjectService) uploadFileToDirectory(destPath string, file io.Reader) error {
	destFile, err := os.Create(destPath)
	if err != nil {
		return err
	}
	defer destFile.Close()

	if _, err := io.Copy(destFile, file); err != nil {
		destFile.Close()
		os.Remove(destPath)
		return err
	}
	return nil
}

func (obs *ObjectService) computeETAG(file io.Reader) (string, error) {
	hash := md5.New()

	_, err := io.Copy(hash, file)
	if err != nil {
		obs.loggerService.Error("failed to hash stream", err)
		return "", err
	}

	etag := `"` + hex.EncodeToString(hash.Sum(nil)) + `"`
	return etag, nil
}

func (obs *ObjectService) createDestPath(bucketID, versionNumber int, objectKey string) (string, error) {
	uploadDir := "./uploads/" + strconv.Itoa(bucketID)
	if err := os.MkdirAll(uploadDir, 0o755); err != nil {
		return "", err
	}
	return filepath.Join(uploadDir, objectKey+"-"+strconv.Itoa(versionNumber)), nil
}

func (obs *ObjectService) Create(ctx context.Context, objectID, bucketID, userID int, fileInfo DTO.IncomingFile) error {
	err := obs.checkPermissions(ctx, bucketID, userID)
	if err != nil {
		return err
	}
	err = obs.checkDoesBucketExist(ctx, bucketID)
	if err != nil {
		return err
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

	etag, err := obs.computeETAG(fileInfo.File)
	if err != nil {
		return err
	}

	if !doesObjectExist {
		object := DTO.Create{
			BucketID:    bucketID,
			ObjectKey:   uuid.NewString(),
			ContentType: fileInfo.ContentType,
			SizeBytes:   fileInfo.SizeBytes,
			ETag:        etag,
		}
		objectKey = object.ObjectKey
		objectID, err = obs.objectRepository.Create(ctx, tx, object)
		if err != nil {
			return err
		}
	}

	newVersionNumber, err := obs.versionRepository.GetNewVersionNumber(ctx, tx, objectID)
	if err != nil {
		return err
	}

	destPath, err := obs.createDestPath(bucketID, newVersionNumber, objectKey)
	if err != nil {
		return err
	}

	err = obs.uploadFileToDirectory(destPath, fileInfo.File)
	if err != nil {
		return err
	}

	newVersionInfo := versionsDTO.Create{
		ObjectID:      objectID,
		VersionNumber: newVersionNumber,
		SizeBytes:     fileInfo.SizeBytes,
		ETag:          etag,
		StorageClass:  "",
	}
	newVersionID, err := obs.versionRepository.Create(ctx, tx, newVersionInfo)
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
