package repository

import (
	"database/sql"

	commonInterfaces "github.com/slodkiadrianek/MINI-BUCKET/common/interfaces"
)

type ObjectRepository struct {
	db            *sql.DB
	loggerService commonInterfaces.Logger
}

func New(db *sql.DB, loggerService commonInterfaces.Logger) *ObjectRepository {
	return &ObjectRepository{
		db:            db,
		loggerService: loggerService,
	}
}

