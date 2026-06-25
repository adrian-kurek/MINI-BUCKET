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
