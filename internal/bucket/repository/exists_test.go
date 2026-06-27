package repository_test

import (
	"context"
	"database/sql"
	"errors"
	"regexp"
	"testing"

	"github.com/DATA-DOG/go-sqlmock"
	bucketRepository "github.com/slodkiadrianek/MINI-BUCKET/internal/bucket/repository"
)

func TestExists(t *testing.T) {
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
				mock.ExpectPrepare(
					regexp.QuoteMeta(`
					SELECT id FROM buckets WHERE id = $1`,
					),
				).
					ExpectQuery().
					WithArgs(sqlmock.AnyArg()).
					WillReturnRows(
						sqlmock.NewRows(
							[]string{"id"},
						).AddRow(
							1,
						),
					)

				return db, ctx
			},
			wantErr: false,
			err:     nil,
		},
		{
			title: "prepare query failed",
			setupMock: func() (*sql.DB, context.Context) {
				db, mock, _ := sqlmock.New()
				ctx := context.Background()
				mock.ExpectPrepare(
					regexp.QuoteMeta(`
					SELECT id FROM buckets WHERE id = $1`,
					),
				).WillReturnError(errors.New("failed to prepare sql query"))

				return db, ctx
			},
			wantErr: true,
			err:     errors.New("failed to prepare sql query"),
		},
		{
			title: "execute query failed",
			setupMock: func() (*sql.DB, context.Context) {
				db, mock, _ := sqlmock.New()
				ctx := context.Background()
				mock.ExpectPrepare(
					regexp.QuoteMeta(`
					SELECT id FROM buckets WHERE id = $1`,
					),
				).ExpectQuery().
					WithArgs(sqlmock.AnyArg()).WillReturnError(errors.New("failed to execute sql query"))

				return db, ctx
			},
			wantErr: true,
			err:     errors.New("failed to execute sql query"),
		},
		{
			title: "bucket not found",
			setupMock: func() (*sql.DB, context.Context) {
				db, mock, _ := sqlmock.New()
				ctx := context.Background()
				mock.ExpectPrepare(
					regexp.QuoteMeta(`
					SELECT id FROM buckets WHERE id = $1`,
					),
				).ExpectQuery().
					WithArgs(sqlmock.AnyArg()).WillReturnError(sql.ErrNoRows)

				return db, ctx
			},
			wantErr: false,
			err:     nil,
		},
	}

	for _, testScenario := range testScenarios {
		t.Run(testScenario.title, func(t *testing.T) {
			db, ctx := testScenario.setupMock()
			loggerService := setupBucketRepositoryDependencies()
			bucketRepository := bucketRepository.NewBucketRepository(loggerService, db)
			_, err := bucketRepository.Exists(ctx, 1)

			if (err != nil) != testScenario.wantErr {
				t.Errorf("Exists() error = %v, wantErr = %v", err, testScenario.wantErr)
			}

			if err != nil && testScenario.err != nil {
				if err.Error() != testScenario.err.Error() {
					t.Errorf("Exists() error = %v, scenarioError = %v", err, testScenario.err)
				}
			}
		})
	}
}
