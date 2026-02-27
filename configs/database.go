// Package config holds whole logic connected with db and cache configuration
package config

import (
	"context"
	"database/sql"
	"errors"
	"fmt"
	"log"
	"os"
	"time"

	"github.com/golang-migrate/migrate/v4"
	"github.com/golang-migrate/migrate/v4/database/postgres"
	_ "github.com/golang-migrate/migrate/v4/source/file"
	_ "github.com/lib/pq"
)

type DB struct {
	DBConnection *sql.DB
}

func NewDB(databaseLink, driver string) (*DB, error) {
	dbConnection, err := sql.Open(driver, databaseLink)
	if err != nil {
		return nil, err
	}

	dbConnection.SetConnMaxIdleTime(30 * time.Second)
	dbConnection.SetMaxOpenConns(20)
	dbConnection.SetMaxIdleConns(20)

	ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
	defer cancel()

	err = dbConnection.PingContext(ctx)
	if err != nil {
		return nil, err
	}

	driverInstance, err := postgres.WithInstance(dbConnection, &postgres.Config{})
	if err != nil {
		return nil, err
	}
	wd, err := os.Getwd()
	if err != nil {
		log.Fatal(err)
	}

	migrationsPath := fmt.Sprintf("file://%s/migrations", wd)

	m, err := migrate.NewWithDatabaseInstance(
		migrationsPath,
		"postgres",
		driverInstance,
	)
	if err != nil {
		log.Fatal(err)
	}
	cmd := os.Args[len(os.Args)-1]
	if cmd == "up" {
		if err := m.Up(); err != nil && !errors.Is(err, migrate.ErrNoChange) {
			log.Fatalf("Migration up failed: %v", err)
		}
		fmt.Println("Migration up completed successfully")
	}

	if cmd == "down" {
		if err := m.Down(); err != nil && !errors.Is(err, migrate.ErrNoChange) {
			log.Fatalf("Migration down failed: %v", err)
		}
		fmt.Println("Migration down completed successfully")
	}

	return &DB{
		DBConnection: dbConnection,
	}, nil
}

func (db *DB) Close() error {
	return db.DBConnection.Close()
}
