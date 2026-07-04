package service

import (
	"context"
	"crypto/md5"
	"database/sql"
	"encoding/hex"
	"io"
	"log"
	"net/http"
	"os"
	"path/filepath"
	"strconv"
	"strings"

	"github.com/google/uuid"
	commonErrors "github.com/slodkiadrianek/MINI-BUCKET/common/errors"
	objectsDTO "github.com/slodkiadrianek/MINI-BUCKET/internal/objects/DTO"
	versionsDTO "github.com/slodkiadrianek/MINI-BUCKET/internal/versions/DTO"
)


func (obs *ObjectService) CheckWritePermissions(ctx context.Context, bucketID, userID int) error {
	permission, err := obs.permissionRepository.GetPermissionValByUserID(ctx, bucketID, userID)
	if err != nil {
		return err
	}
	if permission != 2 && permission != 6 && permission != 3 && permission != 7 {
		obs.loggerService.Info("user tried to perform operation which is not allowed for him", userID)
		return commonErrors.NewAPIError(http.StatusForbidden, "you are not allowed to do this action")
	}
	return nil
}

func (obs *ObjectService) CheckDoesBucketExist(ctx context.Context, bucketID int) error {
	doesBucketExist, err := obs.bucketRepository.Exists(ctx, bucketID)
	if err != nil {
		return err
	}
	if !doesBucketExist {
		return commonErrors.NewAPIError(http.StatusNotFound, "bucket with provided id does not exist")
	}
	return nil
}

func (obs *ObjectService) uploadFileAndComputeETag(destPath string, file io.Reader) (string, error) {
	destFile, err := os.Create(destPath)
	if err != nil {
		return "", err
	}
	defer func() {
		if err := destFile.Close(); err != nil {
			obs.loggerService.Error("failed to close the file", err)
		}
	}()

	hash := md5.New()
	tee := io.TeeReader(file, hash)

	if _, err = io.Copy(destFile, tee); err != nil {
		err = os.Remove(destPath)
		if err != nil {
			obs.loggerService.Error("failed to remove file from disk", destPath)
			return "", err
		}
		return "", err
	}

	return `"` + hex.EncodeToString(hash.Sum(nil)) + `"`, nil
}

func (obs *ObjectService) createDestPath(bucketID int, uuid, objectKey string) (string, error) {
	if objectKey == "" || strings.Contains(
		objectKey,
		"/",
	) || strings.Contains(
		objectKey,
		"\\",
	) || strings.Contains(
		objectKey,
		"..",
	) {
		return "", commonErrors.NewAPIError(http.StatusBadRequest, "invalid file name")
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
		return "", commonErrors.NewAPIError(http.StatusBadRequest, "invalid file name")
	}

	return candidatePath, nil
}

func (obs *ObjectService) upsertObjectMetadata(
	ctx context.Context,
	tx *sql.Tx,
	bucketID int,
	fileInfo objectsDTO.IncomingFile,
	fileUUID,
	etag string,
	versioningEnabled bool,
) error {
	 doesObjectExist,objectID, err := obs.objectRepository.GetObjectID(ctx, fileInfo.FileName, bucketID)
	 // if !doesObjectExist {
	 //  return commonErrors.NewAPIError(http.StatusNotFound, )
	 // }
	if err != nil {
		return err
	}

	if !versioningEnabled {
		return obs.upsertNonVersionedObject(ctx, tx, doesObjectExist, objectID, bucketID, fileInfo, fileUUID, etag)
	}
	return obs.upsertVersionedObject(ctx, tx, doesObjectExist, objectID, bucketID, fileInfo, fileUUID, etag)
}

func (obs *ObjectService) upsertNonVersionedObject(
	ctx context.Context,
	tx *sql.Tx,
	exists bool,
	objectID int,
	bucketID int,
	fileInfo objectsDTO.IncomingFile,
	fileUUID string,
	etag string,
) error {
	if !exists {
		object := objectsDTO.Create{
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

	object := objectsDTO.Update{
		ObjectID:     objectID,
		SizeBytes:    fileInfo.SizeBytes,
		ETag:         etag,
		StorageClass: fileInfo.StorageClass,
		UUID:         fileUUID,
	}
	return obs.objectRepository.Update(ctx, tx, object)
}

func (obs *ObjectService) upsertVersionedObject(
	ctx context.Context,
	tx *sql.Tx,
	exists bool,
	objectID int,
	bucketID int,
	fileInfo objectsDTO.IncomingFile,
	fileUUID string,
	etag string,
) error {
	if !exists {
		object := objectsDTO.Create{
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

func (obs *ObjectService) Upload(ctx context.Context, bucketID, userID int, fileInfo objectsDTO.IncomingFile) error {
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
		err = os.Remove(destPath)
		if err != nil {
			obs.loggerService.Error("failed to remove file from disk", destPath)
			return err
		}
		return err
	}

	tx, err := obs.db.BeginTx(ctx, nil)
	if err != nil {
		err = os.Remove(destPath)
		if err != nil {
			obs.loggerService.Error("failed to remove file from disk", destPath)
			return err
		}
		return err
	}
	defer func() {
		if closeErr := tx.Rollback(); closeErr != nil {
			log.Println("failed to roll back changes", closeErr)
		}
	}()

	if err = obs.upsertObjectMetadata(ctx, tx, bucketID, fileInfo, fileUUID, etag, versioningEnabled); err != nil {
		err = os.Remove(destPath)
		if err != nil {
			obs.loggerService.Error("failed to remove file from disk", destPath)
			return err
		}
		return err
	}

	if err = obs.bucketRepository.UpdateTotalSize(ctx, bucketID, fileInfo.SizeBytes); err != nil {
		err = os.Remove(destPath)
		if err != nil {
			obs.loggerService.Error("failed to remove file from disk", destPath)
			return err
		}
		return err
	}

	if err = tx.Commit(); err != nil {
		err = os.Remove(destPath)
		if err != nil {
			obs.loggerService.Error("failed to remove file from disk", destPath)
			return err
		}
		return err
	}
	return nil
}
