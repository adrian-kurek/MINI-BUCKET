package dto

type Create struct {
	BuckeID          int
	ObjectKey        string
	ContentType      string
	SizeBytes        int
	ETag             string
	CurrentVersionID int
}
