package model

import "time"

type Bucket struct {
	ID                int
	Name              string
	Region            string
	VersioningEnabled bool
	PublicAccess      bool
	EncryptionEnabled bool
	TotalSize         int
	ObjectCount       int
	CreatedAt         time.Time
	Updated           time.Time
}
