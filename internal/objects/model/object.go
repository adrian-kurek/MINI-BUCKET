package model

import "time"

type Object struct {
	ID               int
	BucketID         int
	ObjectKey        string
	ContentType      string
	SizeBytes        int
	ETag             string
	StorageClass     string
	CurrentVersionID int
	createdAt        time.Time
	updatedAt        time.Time
}

type GetMetadata struct {
	ContentType string
	ETAG        string
	SizeBytes   int
	IsDeleted   bool
}
