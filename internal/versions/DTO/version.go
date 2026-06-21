package DTO

type Create struct {
	ObjectID      int
	VersionNumber int
	SizeBytes     int
	ETag          string
	StorageClass  string
}
