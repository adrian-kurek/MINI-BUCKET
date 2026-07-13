package repository_test

import (
	"context"
	"database/sql"
	"errors"
	"regexp"
	"testing"

	"github.com/DATA-DOG/go-sqlmock"
	versionRepository "github.com/slodkiadrianek/MINI-BUCKET/internal/versions/repository"
)

func TestGetUUIDByObjectKey(t *testing.T) {
	type args struct {
		title     string
		setupMock func() *sql.DB
		wantErr   bool
		err       error
	}

	testScenarios := []args{
		{
			title: "with proper data",
			setupMock: func() *sql.DB {
				db, mock, _ := sqlmock.New()
				mock.ExpectPrepare(regexp.QuoteMeta(`SELECT object_uuid FROM object_versions ov 
	INNER JOIN objects o ON o.id = ov.object_id 
	WHERE o.object_key = $1 AND ov.bucket_id = $2  `)).
					ExpectQuery().
					WithArgs(sqlmock.AnyArg(), sqlmock.AnyArg()).
					WillReturnRows(sqlmock.NewRows([]string{"object_uuid"}).AddRow(
						"test",
					))
				return db
			},
			wantErr: false,
			err:     nil,
		},
		{
			title: "failed to execute query",
			setupMock: func() *sql.DB {
				db, mock, _ := sqlmock.New()
				mock.ExpectPrepare(regexp.QuoteMeta(`SELECT object_uuid FROM object_versions ov 
	INNER JOIN objects o ON o.id = ov.object_id 
	WHERE o.object_key = $1 AND ov.bucket_id = $2  `)).
					ExpectQuery().
					WithArgs(sqlmock.AnyArg(), sqlmock.AnyArg()).
					WillReturnError(errors.New("failed to execute query"))
				return db
			},
			wantErr: true,
			err:     errors.New("failed to execute query"),
		},
		{
			title: "failed to prepare query",
			setupMock: func() *sql.DB {
				db, mock, _ := sqlmock.New()
				mock.ExpectPrepare(regexp.QuoteMeta(`SELECT object_uuid FROM object_versions ov 
	INNER JOIN objects o ON o.id = ov.object_id 
	WHERE o.object_key = $1 AND ov.bucket_id = $2  `)).
					WillReturnError(errors.New("failed to prepare query"))
				return db
			},
			wantErr: true,
			err:     errors.New("failed to prepare query"),
		},
	}

	for _, testScenario := range testScenarios {
		t.Run(testScenario.title, func(t *testing.T) {
			loggerService := setupVersionRepositoryDependencies()
			ctx := context.Background()
			db := testScenario.setupMock()
			repo := versionRepository.New(db, loggerService)

			_, err := repo.GetUUIDByObjectKey(ctx, 1, "test")
			if (err != nil) != testScenario.wantErr {
				t.Errorf("GetUUIDByObjectKey() error = %v, wantErr = %v", err, testScenario.wantErr)
			}

			if err != nil && testScenario.err != nil {
				if err.Error() != testScenario.err.Error() {
					t.Errorf("GetUUIDByObjectKey() error = %v, scenarioError = %v", err, testScenario.err)
				}
			}
		})
	}
}

func TestGetUUIDByID(t *testing.T) {
	type args struct {
		title     string
		setupMock func() *sql.DB
		wantErr   bool
		err       error
	}

	testScenarios := []args{
		{
			title: "with proper data",
			setupMock: func() *sql.DB {
				db, mock, _ := sqlmock.New()
				mock.ExpectPrepare(regexp.QuoteMeta(`SELECT object_uuid FROM object_versions WHERE id = $1`)).
					ExpectQuery().
					WithArgs(sqlmock.AnyArg()).
					WillReturnRows(sqlmock.NewRows([]string{"object_uuid"}).AddRow(
						"test",
					))
				return db
			},
			wantErr: false,
			err:     nil,
		},
		{
			title: "failed to execute query",
			setupMock: func() *sql.DB {
				db, mock, _ := sqlmock.New()
				mock.ExpectPrepare(regexp.QuoteMeta(`SELECT object_uuid FROM object_versions WHERE id = $1`)).
					ExpectQuery().
					WithArgs(sqlmock.AnyArg()).
					WillReturnError(errors.New("failed to execute query"))
				return db
			},
			wantErr: true,
			err:     errors.New("failed to execute query"),
		},
		{
			title: "failed to prepare query",
			setupMock: func() *sql.DB {
				db, mock, _ := sqlmock.New()
				mock.ExpectPrepare(regexp.QuoteMeta(`SELECT object_uuid FROM object_versions WHERE id = $1`)).
					WillReturnError(errors.New("failed to prepare query"))
				return db
			},
			wantErr: true,
			err:     errors.New("failed to prepare query"),
		},
	}

	for _, testScenario := range testScenarios {
		t.Run(testScenario.title, func(t *testing.T) {
			loggerService := setupVersionRepositoryDependencies()
			ctx := context.Background()
			db := testScenario.setupMock()
			repo := versionRepository.New(db, loggerService)

			_, err := repo.GetUUIDByID(ctx, 1)
			if (err != nil) != testScenario.wantErr {
				t.Errorf("GetUUIDByID() error = %v, wantErr = %v", err, testScenario.wantErr)
			}

			if err != nil && testScenario.err != nil {
				if err.Error() != testScenario.err.Error() {
					t.Errorf("GetUUIDByID() error = %v, scenarioError = %v", err, testScenario.err)
				}
			}
		})
	}
}

func TestGetMetadata(t *testing.T) {
	type args struct {
		title     string
		setupMock func() *sql.DB
		wantErr   bool
		err       error
	}

	testScenarios := []args{
		{
			title: "with proper data",
			setupMock: func() *sql.DB {
				db, mock, _ := sqlmock.New()
				mock.ExpectPrepare(regexp.QuoteMeta(`
	SELECT 
		ov.size_bytes,
		ov.etag,
		ov.content_type,
		ov.is_deleted
	FROM object_versions ov
	INNER JOIN objects o ON ov.object_id = o.id
	WHERE o.bucket_id = $1
		  AND o.object_key = $2
		  AND (
		        ($3 > 0 AND ov.version_id = $3)
		     OR ($3 <= 0 AND ov.id = o.current_version_id)
		      )
`)).
					ExpectQuery().
					WithArgs(sqlmock.AnyArg(), sqlmock.AnyArg(), sqlmock.AnyArg()).
					WillReturnRows(sqlmock.NewRows([]string{"size_bytes", "etag", "content_type", "is_deleted"}).AddRow(
						1, "test", "text", false,
					))
				return db
			},
			wantErr: false,
			err:     nil,
		},
		{
			title: "failed to execute query",
			setupMock: func() *sql.DB {
				db, mock, _ := sqlmock.New()
				mock.ExpectPrepare(regexp.QuoteMeta(`
	SELECT 
		ov.size_bytes,
		ov.etag,
		ov.content_type,
		ov.is_deleted
	FROM object_versions ov
	INNER JOIN objects o ON ov.object_id = o.id
	WHERE o.bucket_id = $1
		  AND o.object_key = $2
		  AND (
		        ($3 > 0 AND ov.version_id = $3)
		     OR ($3 <= 0 AND ov.id = o.current_version_id)
		      )
`)).
					ExpectQuery().
					WithArgs(sqlmock.AnyArg(), sqlmock.AnyArg(), sqlmock.AnyArg()).
					WillReturnError(errors.New("failed to execute query"))
				return db
			},
			wantErr: true,
			err:     errors.New("failed to execute query"),
		},
		{
			title: "failed to prepare query",
			setupMock: func() *sql.DB {
				db, mock, _ := sqlmock.New()
				mock.ExpectPrepare(regexp.QuoteMeta(`
	SELECT 
		ov.size_bytes,
		ov.etag,
		ov.content_type,
		ov.is_deleted
	FROM object_versions ov
	INNER JOIN objects o ON ov.object_id = o.id
	WHERE o.bucket_id = $1
		  AND o.object_key = $2
		  AND (
		        ($3 > 0 AND ov.version_id = $3)
		     OR ($3 <= 0 AND ov.id = o.current_version_id)
		      )
`)).
					WillReturnError(errors.New("failed to prepare query"))
				return db
			},
			wantErr: true,
			err:     errors.New("failed to prepare query"),
		},
	}

	for _, testScenario := range testScenarios {
		t.Run(testScenario.title, func(t *testing.T) {
			loggerService := setupVersionRepositoryDependencies()
			ctx := context.Background()
			db := testScenario.setupMock()
			repo := versionRepository.New(db, loggerService)

			_, err := repo.GetMetadata(ctx, 1, "test", 1)
			if (err != nil) != testScenario.wantErr {
				t.Errorf("GetMetadata() error = %v, wantErr = %v", err, testScenario.wantErr)
			}

			if err != nil && testScenario.err != nil {
				if err.Error() != testScenario.err.Error() {
					t.Errorf("GetMetadata() error = %v, scenarioError = %v", err, testScenario.err)
				}
			}
		})
	}
}
