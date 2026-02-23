package repository

import (
	"database/sql"

	commonInterfaces "github.com/slodkiadrianek/MINI-BUCKET/internal/common/interfaces"
)

type BucketRepository struct {
	logger commonInterfaces.Logger
	db *sql.DB
}