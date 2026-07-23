package DTO

import (
	"io"
)

type Create struct {
	BucketID     int
	ObjectKey    string
	ContentType  string
	SizeBytes    int
	ETag         string
	StorageClass string
	UUID         string
}

type Update struct {
	ObjectID     int
	SizeBytes    int
	ETag         string
	StorageClass string
	UUID         string
}

type IncomingFile struct {
	File         io.Reader
	FileName     string
	ContentType  string
	StorageClass string
	SizeBytes    int
}

type deleteFile struct {
	ObjectKey string `json:"object_key" validate:"required,file"`
	VersionID string `json:"version_id" validate:"int"`
}

type DeleteManyFiles struct {
	FilesToDelete []deleteFile `json:"files_to_delete" validate:"unique=ObjectKey"`
}
