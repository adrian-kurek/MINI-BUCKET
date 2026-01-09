// Package config holds whole logic connected with db and cache configuration
package config

import (
	"database/sql"

	_ "github.com/lib/pq"
)

type DB struct {
	DBConnection *sql.DB
}

func NewDB(databaseLink, driver string) (*DB, error) {
	dbConnection, err := sql.Open(driver, databaseLink)
	if err != nil {
		return &DB{}, err
	}

	err = dbConnection.Ping()
	if err != nil {
		return &DB{}, err
	}

	return &DB{
		DBConnection: dbConnection,
	}, nil
}
