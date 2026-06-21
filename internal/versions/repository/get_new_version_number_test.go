package repository

import (
	"context"
	"database/sql"
	"errors"
	"regexp"
	"testing"

	"github.com/DATA-DOG/go-sqlmock"
)

func TestGetObjectKey(t *testing.T) {
	type args struct {
		title     string
		setupMock func() (*sql.DB, context.Context)
		wantErr   bool
		err       error
	}

	testScenarios := []args{
		{
			title: "with proper data",
			setupMock: func() (*sql.DB, context.Context) {
				db, mock, _ := sqlmock.New()
				ctx := context.Background()
				mock.ExpectBegin()
				mock.ExpectPrepare(regexp.QuoteMeta("SELECT COALESCE(MAX(version_number), 0) + 1 as new_version_num FROM object_versions WHERE object_id = $1")).
					ExpectQuery().
					WithArgs(sqlmock.AnyArg()).
					WillReturnRows(sqlmock.NewRows([]string{"new_version_num"}).AddRow(
						1,
					))
				mock.ExpectCommit()
				return db, ctx
			},
			wantErr: false,
			err:     nil,
		},
		{
			title: "failed to prepare sql query",
			setupMock: func() (*sql.DB, context.Context) {
				db, mock, _ := sqlmock.New()
				ctx := context.Background()
				mock.ExpectBegin()
				mock.ExpectPrepare(regexp.QuoteMeta("SELECT COALESCE(MAX(version_number), 0) + 1 as new_version_num FROM object_versions WHERE object_id = $1")).WillReturnError(errors.New("failed to prepare sql query"))
				mock.ExpectRollback()
				return db, ctx
			},
			wantErr: true,
			err:     errors.New("failed to prepare sql query"),
		},
		{
			title: "failed to execute sql query",
			setupMock: func() (*sql.DB, context.Context) {
				db, mock, _ := sqlmock.New()
				ctx := context.Background()
				mock.ExpectBegin()
				mock.ExpectPrepare(regexp.QuoteMeta("SELECT COALESCE(MAX(version_number), 0) + 1 as new_version_num FROM object_versions WHERE object_id = $1")).
					ExpectQuery().
					WithArgs(sqlmock.AnyArg()).WillReturnError(errors.New("failed to execute sql query"))
				mock.ExpectRollback()
				return db, ctx
			},
			wantErr: true,
			err:     errors.New("failed to execute sql query"),
		},
		{
			title: "object not found",
			setupMock: func() (*sql.DB, context.Context) {
				db, mock, _ := sqlmock.New()
				ctx := context.Background()
				mock.ExpectBegin()
				mock.ExpectPrepare(regexp.QuoteMeta("SELECT COALESCE(MAX(version_number), 0) + 1 as new_version_num FROM object_versions WHERE object_id = $1")).
					ExpectQuery().
					WithArgs(sqlmock.AnyArg()).WillReturnError(sql.ErrNoRows)
				mock.ExpectRollback()
				return db, ctx
			},
			wantErr: true,
			err:     sql.ErrNoRows,
		},
	}

	for _, testScenario := range testScenarios {
		t.Run(testScenario.title, func(t *testing.T) {
			loggerService := setupVersionRepositoryDependencies()
			db, ctx := testScenario.setupMock()
			versionRepository := NewVersionRepository(db, loggerService)
			tx, err := db.BeginTx(context.Background(), nil)
			if err != nil {
				panic(err)
			}
			defer tx.Rollback()

			_, err = versionRepository.GetNewVersionNumber(ctx, tx, 1)
			if (err != nil) != testScenario.wantErr {
				t.Errorf("GetNewVersionNumber() error = %v, wantErr = %v", err, testScenario.wantErr)
			}

			if err != nil && testScenario.err != nil {
				if err.Error() != testScenario.err.Error() {
					t.Errorf("GetNewVersionNumber() error = %v, scenarioError = %v", err, testScenario.err)
				}
			}
		})
	}
}
