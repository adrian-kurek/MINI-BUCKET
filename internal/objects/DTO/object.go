package DTO

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
	File        io.Reader
	ContentType string
	SizeBytes   int
}
