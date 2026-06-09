package dto

import (
	"io"
)

type Create struct {
	BucketID    int
	ObjectKey   string
	ContentType string
	SizeBytes   int
	ETag        string
}

type IncomingFile struct {
	Body        io.Reader
	ContentType string
	SizeBytes   int
}

type CreateVersion struct {
	ObjectID      int
	VersionNumber int
	SizeBytes     int
	ETag          string
	StorageClass  string
}
