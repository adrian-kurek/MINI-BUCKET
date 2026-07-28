package repository_test

import (
	"context"
	"database/sql"
	"errors"
	"fmt"
	"regexp"
	"testing"

	"github.com/DATA-DOG/go-sqlmock"
	versionRepository "github.com/slodkiadrianek/MINI-BUCKET/internal/versions/repository"
)

func TestDelete(t *testing.T) {
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
				mock.ExpectPrepare(regexp.QuoteMeta("DELETE FROM object_versions WHERE id = $1")).
					ExpectExec().
					WithArgs(sqlmock.AnyArg()).
					WillReturnResult(sqlmock.NewResult(0, 1))

				return db
			},
			wantErr: false,
			err:     nil,
		},
		{
			title: "failed to execute query",
			setupMock: func() *sql.DB {
				db, mock, _ := sqlmock.New()
				mock.ExpectPrepare(regexp.QuoteMeta("DELETE FROM object_versions WHERE id = $1")).
					ExpectExec().
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
				mock.ExpectPrepare(regexp.QuoteMeta("DELETE FROM object_versions WHERE id = $1")).
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

			err := repo.Delete(ctx, 1)
			if (err != nil) != testScenario.wantErr {
				t.Errorf("Delete() error = %v, wantErr = %v", err, testScenario.wantErr)
			}

			if err != nil && testScenario.err != nil {
				if err.Error() != testScenario.err.Error() {
					t.Errorf("Delete() error = %v, scenarioError = %v", err, testScenario.err)
				}
			}
		})
	}
}

func TestDeleteMany(t *testing.T) {
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
				placholder := "$1"
				expectedQuery := fmt.Sprintf("DELETE FROM object_versions ov INNER JOIN objects o ON o.id = ov.object_id  WHERE ov.id IN ( %s ) AND o.bucket_id = $%d", placholder, 2)
				mock.ExpectPrepare(regexp.QuoteMeta(expectedQuery)).
					ExpectExec().
					WithArgs(sqlmock.AnyArg(), sqlmock.AnyArg()).
					WillReturnResult(sqlmock.NewResult(0, 1))

				return db
			},
			wantErr: false,
			err:     nil,
		},
		{
			title: "failed to execute query",
			setupMock: func() *sql.DB {
				db, mock, _ := sqlmock.New()
				placholder := "$1"
				expectedQuery := fmt.Sprintf("DELETE FROM object_versions ov INNER JOIN objects o ON o.id = ov.object_id  WHERE ov.id IN ( %s ) AND o.bucket_id = $%d", placholder, 2)
				mock.ExpectPrepare(regexp.QuoteMeta(expectedQuery)).
					ExpectExec().
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
				placholder := "$1"
				expectedQuery := fmt.Sprintf("DELETE FROM object_versions ov INNER JOIN objects o ON o.id = ov.object_id  WHERE ov.id IN ( %s ) AND o.bucket_id = $%d", placholder, 2)
				mock.ExpectPrepare(regexp.QuoteMeta(expectedQuery)).
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

			err := repo.DeleteMany(ctx, []int{1}, 1)
			if (err != nil) != testScenario.wantErr {
				t.Errorf("DeleteMany() error = %v, wantErr = %v", err, testScenario.wantErr)
			}

			if err != nil && testScenario.err != nil {
				if err.Error() != testScenario.err.Error() {
					t.Errorf("DeleteMany() error = %v, scenarioError = %v", err, testScenario.err)
				}
			}
		})
	}
}

func TestCreateManyDeleteMarkers(t *testing.T) {
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
				mock.ExpectBegin()
				placholder := "($1,'',TRUE, 0,'','STANDARD',NOW(),NOW())"
				expectedQuery := fmt.Sprintf(`INSERT INTO object_versions(
					object_id,
					object_uuid,
					is_deleted,
					size_bytes,
					etag,
					storage_class,
					created_at,
					updated_at
				) VALUES %s RETURNING id`, placholder)
				mock.ExpectPrepare(regexp.QuoteMeta(expectedQuery)).
					ExpectQuery().
					WithArgs(sqlmock.AnyArg()).
					WillReturnRows(sqlmock.NewRows([]string{"id"}).AddRow(1))
				mock.ExpectCommit()

				return db
			},
			wantErr: false,
			err:     nil,
		},
		{
			title: "failed to execute query",
			setupMock: func() *sql.DB {
				db, mock, _ := sqlmock.New()
				mock.ExpectBegin()
				placholder := "($1,'',TRUE, 0,'','STANDARD',NOW(),NOW())"
				expectedQuery := fmt.Sprintf(`INSERT INTO object_versions(
					object_id,
					object_uuid,
					is_deleted,
					size_bytes,
					etag,
					storage_class,
					created_at,
					updated_at
				) VALUES %s RETURNING id`, placholder)
				mock.ExpectPrepare(regexp.QuoteMeta(expectedQuery)).
					ExpectQuery().
					WithArgs(sqlmock.AnyArg()).
					WillReturnError(errors.New("failed to execute query"))
				mock.ExpectRollback()

				return db
			},
			wantErr: true,
			err:     errors.New("failed to execute query"),
		},
		{
			title: "failed to prepare query",
			setupMock: func() *sql.DB {
				db, mock, _ := sqlmock.New()
				mock.ExpectBegin()
				placholder := "($1,'',TRUE, 0,'','STANDARD',NOW(),NOW())"
				expectedQuery := fmt.Sprintf(`INSERT INTO object_versions(
					object_id,
					object_uuid,
					is_deleted,
					size_bytes,
					etag,
					storage_class,
					created_at,
					updated_at
				) VALUES %s RETURNING id`, placholder)
				mock.ExpectPrepare(regexp.QuoteMeta(expectedQuery)).
					WillReturnError(errors.New("failed to prepare query"))

				mock.ExpectRollback()
				return db
			},
			wantErr: true,
			err:     errors.New("failed to prepare query"),
		},
		{
			title: "failed to find id",
			setupMock: func() *sql.DB {
				db, mock, _ := sqlmock.New()
				mock.ExpectBegin()
				placholder := "($1,'',TRUE, 0,'','STANDARD',NOW(),NOW())"
				expectedQuery := fmt.Sprintf(`INSERT INTO object_versions(
					object_id,
					object_uuid,
					is_deleted,
					size_bytes,
					etag,
					storage_class,
					created_at,
					updated_at
				) VALUES %s RETURNING id`, placholder)
				mock.ExpectPrepare(regexp.QuoteMeta(expectedQuery)).
					ExpectQuery().
					WithArgs(sqlmock.AnyArg()).
					WillReturnRows(sqlmock.NewRows([]string{"id"}))

				mock.ExpectRollback()
				return db
			},
			wantErr: true,
			err:     errors.New("api error: "),
		},

		{
			title: "failed to scan row",
			setupMock: func() *sql.DB {
				db, mock, _ := sqlmock.New()
				mock.ExpectBegin()
				placholder := "($1,'',TRUE, 0,'','STANDARD',NOW(),NOW())"
				expectedQuery := fmt.Sprintf(`INSERT INTO object_versions(
					object_id,
					object_uuid,
					is_deleted,
					size_bytes,
					etag,
					storage_class,
					created_at,
					updated_at
				) VALUES %s RETURNING id`, placholder)
				mock.ExpectPrepare(regexp.QuoteMeta(expectedQuery)).
					ExpectQuery().
					WithArgs(sqlmock.AnyArg()).
					WillReturnRows(sqlmock.NewRows([]string{"id"}).AddRow(1).RowError(0, errors.New("failed to scan row")))

				mock.ExpectRollback()
				return db
			},
			wantErr: true,
			err:     errors.New("failed to scan row"),
		},
	}

	for _, testScenario := range testScenarios {
		t.Run(testScenario.title, func(t *testing.T) {
			loggerService := setupVersionRepositoryDependencies()
			ctx := context.Background()
			db := testScenario.setupMock()
			repo := versionRepository.New(db, loggerService)
			tx, err := db.BeginTx(context.Background(), nil)
			if err != nil {
				panic(err)
			}

			_, err = repo.CreateManyDeleteMarkers(ctx, tx, []int{1})

			if err != nil {
				if rbErr := tx.Rollback(); rbErr != nil {
					t.Errorf("failed to roll back query: %s", rbErr.Error())
				}
			} else {
				if commitErr := tx.Commit(); commitErr != nil {
					t.Errorf("failed to commit query: %s", commitErr.Error())
				}
			}
			if (err != nil) != testScenario.wantErr {
				t.Errorf("CreateManyDeleteMarkers() error = %v, wantErr = %v", err, testScenario.wantErr)
			}

			if err != nil && testScenario.err != nil {
				if err.Error() != testScenario.err.Error() {
					t.Errorf("CreateManyDeleteMarkers() error = %v, scenarioError = %v", err, testScenario.err)
				}
			}
		})
	}
}
