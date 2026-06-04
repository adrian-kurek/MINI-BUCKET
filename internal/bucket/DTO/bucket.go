package dto

type CreateBucket struct {
	Name string `json:"name" validate:"required,min=3,max=50"`
	VersioningEnabled bool   `json:"versioningEnabled"`
	PublicAccess bool   `json:"publicAccess"`
	StorageClass string `json:"storageClass" validate:"required,oneof=STANDARD INFREQUENT_ACCESS ARCHIVE"`
	EncryptionEnabled bool   `json:"encryptionEnabled"`
}
