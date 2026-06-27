package service

import (
	"context"
	"crypto/md5"
	"database/sql"
	"encoding/hex"
	"fmt"
	"io"
	"os"
	"path/filepath"
	"strconv"
	"strings"

	"github.com/google/uuid"
	commonErrors "github.com/slodkiadrianek/MINI-BUCKET/common/errors"
	commonInterfaces "github.com/slodkiadrianek/MINI-BUCKET/common/interfaces"
	DTO "github.com/slodkiadrianek/MINI-BUCKET/internal/objects/DTO"
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
	}
	ObjectRepository interface {
		Create(ctx context.Context, tx *sql.Tx, file objectsDTO.Create) (int, error)
		GetObjectID(ctx context.Context, objectKey string, bucketID int) (bool, int, error)
		UpdateCurrentVersionIDOfObject(ctx context.Context, tx *sql.Tx, objectID, versionID int) error
		GetMetadata(ctx context.Context, bucketID int, objectKey string) (model.GetMetadata, error)
		SoftDeleteVersion(ctx context.Context, objectID int, objectKey string, versionNumber int) error
		SoftDeleteObject(ctx context.Context, bucketID int, objectKey string) error
		HardDeleteObject(ctx context.Context, bucketID int, objectKey string) error
		HardDeleteVersion(ctx context.Context, bucketID int, objectKey string, versionNumber int) error
		Update(ctx context.Context, tx *sql.Tx, file DTO.Update) error
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

func NewObjectService(loggerService commonInterfaces.Logger, objectRepository ObjectRepository, permissionRepository PermissionRepository, bucketRepository BucketRepository, db *sql.DB, versionRepository VersionRepository) *ObjectService {
	return &ObjectService{
		loggerService:        loggerService,
		objectRepository:     objectRepository,
		permissionRepository: permissionRepository,
		bucketRepository:     bucketRepository,
		versionRepository:    versionRepository,
		db:                   db,
	}
}

func (obs *ObjectService) CheckWritePermissions(ctx context.Context, bucketID, userID int) error {
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

func (obs *ObjectService) CheckDoesBucketExist(ctx context.Context, bucketID int) error {
	doesBucketExist, err := obs.bucketRepository.Exists(ctx, bucketID)
	if err != nil {
		return err
	}
	if !doesBucketExist {
		return commonErrors.NewAPIError(404, "bucket with provided id does not exist")
	}
	return nil
}

func (obs *ObjectService) uploadFileAndComputeETag(destPath string, file io.Reader) (string, error) {
	destFile, err := os.Create(destPath)
	if err != nil {
		return "", err
	}
	defer destFile.Close()

	hash := md5.New()
	tee := io.TeeReader(file, hash)

	if _, err := io.Copy(destFile, tee); err != nil {
		os.Remove(destPath)
		return "", err
	}

	return `"` + hex.EncodeToString(hash.Sum(nil)) + `"`, nil
}

func (obs *ObjectService) createDestPath(bucketID int, uuid, objectKey string) (string, error) {
	if objectKey == "" || strings.Contains(objectKey, "/") || strings.Contains(objectKey, "\\") || strings.Contains(objectKey, "..") {
		fmt.Println(objectKey)
		return "", commonErrors.NewAPIError(400, "invalid file name")
	}

	uploadDir := "./uploads/" + strconv.Itoa(bucketID)
	if err := os.MkdirAll(uploadDir, 0o755); err != nil {
		return "", err
	}

	candidatePath := filepath.Join(uploadDir, objectKey+"-"+uuid)

	absUploadDir, err := filepath.Abs(uploadDir)
	if err != nil {
		return "", err
	}
	absCandidatePath, err := filepath.Abs(candidatePath)
	if err != nil {
		return "", err
	}

	uploadDirWithSep := absUploadDir + string(os.PathSeparator)
	if absCandidatePath != absUploadDir && !strings.HasPrefix(absCandidatePath, uploadDirWithSep) {
		return "", commonErrors.NewAPIError(400, "invalid file name")
	}

	return candidatePath, nil
}

func (obs *ObjectService) upsertObjectMetadata(ctx context.Context, tx *sql.Tx, bucketID int, fileInfo DTO.IncomingFile, fileUUID, etag string, versioningEnabled bool) error {
	doesObjectExist, objectID, err := obs.objectRepository.GetObjectID(ctx, fileInfo.FileName, bucketID)
	if err != nil {
		return err
	}

	if !versioningEnabled {
		return obs.upsertNonVersionedObject(ctx, tx, doesObjectExist, objectID, bucketID, fileInfo, fileUUID, etag)
	}
	return obs.upsertVersionedObject(ctx, tx, doesObjectExist, objectID, bucketID, fileInfo, fileUUID, etag)
}

func (obs *ObjectService) upsertNonVersionedObject(ctx context.Context, tx *sql.Tx, exists bool, objectID, bucketID int, fileInfo DTO.IncomingFile, fileUUID, etag string) error {
	if !exists {
		object := DTO.Create{
			BucketID:     bucketID,
			ObjectKey:    fileInfo.FileName,
			ContentType:  fileInfo.ContentType,
			SizeBytes:    fileInfo.SizeBytes,
			ETag:         etag,
			UUID:         fileUUID,
			StorageClass: fileInfo.StorageClass,
		}
		_, err := obs.objectRepository.Create(ctx, tx, object)
		return err
	}

	object := DTO.Update{
		ObjectID:     objectID,
		SizeBytes:    fileInfo.SizeBytes,
		ETag:         etag,
		StorageClass: fileInfo.StorageClass,
		UUID:         fileUUID,
	}
	return obs.objectRepository.Update(ctx, tx, object)
}

func (obs *ObjectService) upsertVersionedObject(ctx context.Context, tx *sql.Tx, exists bool, objectID, bucketID int, fileInfo DTO.IncomingFile, fileUUID, etag string) error {
	if !exists {
		object := DTO.Create{
			BucketID:    bucketID,
			ObjectKey:   fileInfo.FileName,
			ContentType: fileInfo.ContentType,
		}
		newID, err := obs.objectRepository.Create(ctx, tx, object)
		if err != nil {
			return err
		}
		objectID = newID
	}

	newVersionInfo := versionsDTO.Create{
		ObjectID:     objectID,
		UUID:         fileUUID,
		SizeBytes:    fileInfo.SizeBytes,
		ETag:         etag,
		StorageClass: fileInfo.StorageClass,
	}

	newVersionID, err := obs.versionRepository.Create(ctx, tx, newVersionInfo)
	if err != nil {
		return err
	}
	return obs.objectRepository.UpdateCurrentVersionIDOfObject(ctx, tx, objectID, newVersionID)
}

func (obs *ObjectService) Upload(ctx context.Context, bucketID, userID int, fileInfo DTO.IncomingFile) error {
	if err := obs.CheckWritePermissions(ctx, bucketID, userID); err != nil {
		return err
	}
	if err := obs.CheckDoesBucketExist(ctx, bucketID); err != nil {
		return err
	}

	fileUUID := uuid.New().String()
	destPath, err := obs.createDestPath(bucketID, fileUUID, fileInfo.FileName)
	if err != nil {
		return err
	}

	etag, err := obs.uploadFileAndComputeETag(destPath, fileInfo.File)
	if err != nil {
		return err
	}

	versioningEnabled, err := obs.bucketRepository.IsVersioningEnabled(ctx, bucketID)
	if err != nil {
		os.Remove(destPath)
		return err
	}

	tx, err := obs.db.BeginTx(ctx, nil)
	if err != nil {
		os.Remove(destPath)
		return err
	}
	defer tx.Rollback()

	if err := obs.upsertObjectMetadata(ctx, tx, bucketID, fileInfo, fileUUID, etag, versioningEnabled); err != nil {
		os.Remove(destPath)
		return err
	}

	if err := obs.bucketRepository.UpdateTotalSize(ctx, bucketID, fileInfo.SizeBytes); err != nil {
		os.Remove(destPath)
		return err
	}

	if err := tx.Commit(); err != nil {
		os.Remove(destPath)
		return err
	}
	return nil
}
