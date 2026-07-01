package repository_test

import (
	"context"
	"database/sql"
	"errors"
	"regexp"
	"testing"

	"github.com/DATA-DOG/go-sqlmock"
	objectRepository "github.com/slodkiadrianek/MINI-BUCKET/internal/objects/repository"
)

func TestGetObjectID(t *testing.T) {
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
				mock.ExpectPrepare(regexp.QuoteMeta("SELECT id FROM objects WHERE object_key = $1 AND bucket_id = $2")).
					ExpectQuery().
					WithArgs(sqlmock.AnyArg(), sqlmock.AnyArg()).
					WillReturnRows(sqlmock.NewRows([]string{"id"}).AddRow(
						1,
					))
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
				mock.ExpectPrepare(regexp.QuoteMeta("SELECT id FROM objects WHERE object_key = $1 AND bucket_id = $2")).
					WillReturnError(errors.New("failed to prepare sql query"))
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
				mock.ExpectPrepare(regexp.QuoteMeta("SELECT id FROM objects WHERE object_key = $1 AND bucket_id = $2")).
					ExpectQuery().
					WithArgs(sqlmock.AnyArg(), sqlmock.AnyArg()).
					WillReturnError(errors.New("failed to execute sql query"))
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
				mock.ExpectPrepare(regexp.QuoteMeta("SELECT id FROM objects WHERE object_key = $1 AND bucket_id = $2")).
					ExpectQuery().
					WithArgs(sqlmock.AnyArg(), sqlmock.AnyArg()).WillReturnError(sql.ErrNoRows)
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
			repo := objectRepository.New(db, loggerService)

			_, _, err := repo.GetObjectID(ctx, "", 1)
			if (err != nil) != testScenario.wantErr {
				t.Errorf("GetObjectID() error = %v, wantErr = %v", err, testScenario.wantErr)
			}

			if err != nil && testScenario.err != nil {
				if err.Error() != testScenario.err.Error() {
					t.Errorf("GetObjectID() error = %v, scenarioError = %v", err, testScenario.err)
				}
			}
		})
	}
}
