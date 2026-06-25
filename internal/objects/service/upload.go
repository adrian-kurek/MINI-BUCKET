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
		IsVersioningEnabled(ctx context.Context, bucketID int) (bool, error)
		UpdateTotalSize(ctx context.Context, bucketID, sizeBytes int) error
	}
	versionRepository interface {
		GetNewVersionNumber(ctx context.Context, tx *sql.Tx, objectID int) (int, error)
		Create(ctx context.Context, tx *sql.Tx, file versionsDTO.Create) (int, error)
	}
	objectRepository interface {
		Create(ctx context.Context, tx *sql.Tx, file objectsDTO.Create) (int, error)
		GetObjectID(ctx context.Context, objectKey string, bucketID int) (bool, int, error)
		UpdateCurrentVersionIDOfObject(ctx context.Context, tx *sql.Tx, objectID, versionID int) error
		GetMetadata(ctx context.Context, bucketID int, objectKey string, versionNumber int) (model.GetMetadata, error)
		SoftDeleteVersion(ctx context.Context, objectID int, objectKey string, versionNumber int) error
		SoftDeleteObject(ctx context.Context, bucketID int, objectKey string) error
		HardDeleteObject(ctx context.Context, bucketID int, objectKey string) error
		HardDeleteVersion(ctx context.Context, bucketID int, objectKey string, versionNumber int) error
		Update(ctx context.Context, tx *sql.Tx, file DTO.Update) error
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

func (obs *ObjectService) checkWritePermissions(ctx context.Context, bucketID, userID int) error {
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

func (obs *ObjectService) createDestPath(bucketID int, uuid, objectKey string) (string, error) {
	uploadDir := "./uploads/" + strconv.Itoa(bucketID)
	if err := os.MkdirAll(uploadDir, 0o755); err != nil {
		return "", err
	}
	return filepath.Join(uploadDir, objectKey+"-"+uuid), nil
}

func (obs *ObjectService) Create(ctx context.Context, objectID, bucketID, userID int, fileInfo DTO.IncomingFile) error {
	err := obs.checkWritePermissions(ctx, bucketID, userID)
	if err != nil {
		return err
	}

	err = obs.checkDoesBucketExist(ctx, bucketID)
	if err != nil {
		return err
	}

	uuid := uuid.New().String()

	destPath, err := obs.createDestPath(bucketID, uuid, fileInfo.FileName)
	if err != nil {
		return err
	}

	err = obs.uploadFileToDirectory(destPath, fileInfo.File)
	if err != nil {
		return err
	}

	etag, err := obs.computeETAG(fileInfo.File)
	if err != nil {
		os.Remove(destPath)
		return err
	}

	isVersioningEnabled, err := obs.bucketRepository.IsVersioningEnabled(ctx, bucketID)
	if err != nil {
		os.Remove(destPath)
		return err
	}

	doesObjectExist, objectID, err := obs.objectRepository.GetObjectID(ctx, fileInfo.FileName, bucketID)
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

	if !isVersioningEnabled {
		if !doesObjectExist {
			object := DTO.Create{
				BucketID:    bucketID,
				ObjectKey:   fileInfo.FileName,
				ContentType: fileInfo.ContentType,
				SizeBytes:   fileInfo.SizeBytes,
				ETag:        etag,
				UUID:        uuid,
			}
			_, err = obs.objectRepository.Create(ctx, tx, object)
			if err != nil {
				tx.Rollback()
				os.Remove(destPath)
				return err
			}
		} else {
			object := DTO.Update{
				ObjectID:     objectID,
				SizeBytes:    fileInfo.SizeBytes,
				ETag:         etag,
				StorageClass: fileInfo.StorageClass,
				UUID:         uuid,
			}
			err = obs.objectRepository.Update(ctx, tx, object)
			if err != nil {
				tx.Rollback()
				os.Remove(destPath)
				return err
			}
		}
	} else {
		if !doesObjectExist {
			object := DTO.Create{
				BucketID:    bucketID,
				ObjectKey:   fileInfo.FileName,
				ContentType: fileInfo.ContentType,
				SizeBytes:   0,
				ETag:        "",
				UUID:        "",
			}
			_, err = obs.objectRepository.Create(ctx, tx, object)
			if err != nil {
				tx.Rollback()
				os.Remove(destPath)
				return err
			}
		}
		newVersionInfo := versionsDTO.Create{
			ObjectID:     objectID,
			UUID:         uuid,
			SizeBytes:    fileInfo.SizeBytes,
			ETag:         etag,
			StorageClass: "",
		}
		newVersionID, err := obs.versionRepository.Create(ctx, tx, newVersionInfo)
		if err != nil {
			tx.Rollback()
			os.Remove(destPath)
			return err
		}

		err = obs.objectRepository.UpdateCurrentVersionIDOfObject(ctx, tx, objectID, newVersionID)
		if err != nil {
			tx.Rollback()
			os.Remove(destPath)
			return err
		}
	}

	err = obs.bucketRepository.UpdateTotalSize(ctx, bucketID, fileInfo.SizeBytes)
	if err != nil {
		tx.Rollback()
		os.Remove(destPath)
		return err
	}

	if err := tx.Commit(); err != nil {
		os.Remove(destPath)
		return err
	}
	return nil
}
