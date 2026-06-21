package repository

import (
	"context"
	"database/sql"
	"errors"
	"regexp"
	"testing"

	"github.com/DATA-DOG/go-sqlmock"
)

func TestUpdateCurrentVersionOfObject(t *testing.T) {
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
				mock.ExpectPrepare(regexp.QuoteMeta("UPDATE objects SET current_version_id = $1 WHERE id = $2")).
					ExpectExec().
					WithArgs(sqlmock.AnyArg(), sqlmock.AnyArg()).
					WillReturnResult(sqlmock.NewResult(1, 1))
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

				mock.ExpectPrepare(regexp.QuoteMeta("UPDATE objects SET current_version_id = $1 WHERE id = $2")).WillReturnError(errors.New("failed to prepare sql query"))
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
				mock.ExpectPrepare(regexp.QuoteMeta("UPDATE objects SET current_version_id = $1 WHERE id = $2")).
					ExpectExec().
					WithArgs(sqlmock.AnyArg(), sqlmock.AnyArg()).WillReturnError(errors.New("failed to execute sql query"))
				mock.ExpectRollback()
				return db, ctx
			},
			wantErr: true,
			err:     errors.New("failed to execute sql query"),
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

			err = objectRepository.UpdateCurrentVersionIDOfObject(ctx, tx, 1, 1)
			if (err != nil) != testScenario.wantErr {
				t.Errorf("UpdateCurrentVersionOfObject() error = %v, wantErr = %v", err, testScenario.wantErr)
			}

			if err != nil && testScenario.err != nil {
				if err.Error() != testScenario.err.Error() {
					t.Errorf("UpdateCurrentVersionOfObject() error = %v, scenarioError = %v", err, testScenario.err)
				}
			}
		})
	}
}
