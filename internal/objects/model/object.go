package model

import "time"

type Object struct {
	ID               int
	BucketID         int
	ObjectKey        string
	ContentType      string
	SizeBytes        int
	ETag             string
	CurrentVersionID int
	IsDeleted        bool
	createdAt        time.Time
	updatedAt        time.Time
}
