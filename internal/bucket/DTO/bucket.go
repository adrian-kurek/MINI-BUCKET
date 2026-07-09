package DTO

type BucketInput struct {
	Name              string `json:"name" validate:"required,min=3,max=50"`
	VersioningEnabled bool   `json:"versioningEnabled" validate:"boolean"`
	PublicAccess      bool   `json:"publicAccess" validate:"boolean"`
	StorageClass      string `json:"storageClass" validate:"required,oneof=STANDARD INFREQUENT_ACCESS ARCHIVE"`
	EncryptionEnabled bool   `json:"encryptionEnabled" validate:"boolean"`
}
