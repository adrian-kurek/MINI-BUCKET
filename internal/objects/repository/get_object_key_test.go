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
				mock.ExpectPrepare(regexp.QuoteMeta("SELECT object_key FROM objects WHERE id = $1")).
					ExpectQuery().
					WithArgs(sqlmock.AnyArg()).
					WillReturnRows(sqlmock.NewRows([]string{"object_key"}).AddRow(
						"822a9393-9e17-40b9-b897-699c5c95c06b",
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
				mock.ExpectPrepare(regexp.QuoteMeta("SELECT object_key FROM objects WHERE id = $1")).WillReturnError(errors.New("failed to prepare sql query"))
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
				mock.ExpectPrepare(regexp.QuoteMeta("SELECT object_key FROM objects WHERE id = $1")).
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
				mock.ExpectPrepare(regexp.QuoteMeta("SELECT object_key FROM objects WHERE id = $1")).
					ExpectQuery().
					WithArgs(sqlmock.AnyArg()).WillReturnError(sql.ErrNoRows)
				mock.ExpectRollback()
				return db, ctx
			},
			wantErr: false,
			err:     nil,
		},
	}

	for _, testScenario := range testScenarios {
		t.Run(testScenario.title, func(t *testing.T) {
			loggerService := setupObjectRepositoryDependencies()
			db, ctx := testScenario.setupMock()
			objectRepository := NewObjectRepository(db, loggerService)
			tx, err := db.BeginTx(context.Background(), nil)
			if err != nil {
				panic(err)
			}
			defer tx.Rollback()

			_, _, err = objectRepository.GetObjectKey(ctx, tx, 1)
			if (err != nil) != testScenario.wantErr {
				t.Errorf("GetObjectKey() error = %v, wantErr = %v", err, testScenario.wantErr)
			}

			if err != nil && testScenario.err != nil {
				if err.Error() != testScenario.err.Error() {
					t.Errorf("GetObjectKey() error = %v, scenarioError = %v", err, testScenario.err)
				}
			}
		})
	}
}
