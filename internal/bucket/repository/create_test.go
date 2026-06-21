package repository

import (
	"context"
	"database/sql"
	"errors"
	"testing"

	"github.com/DATA-DOG/go-sqlmock"
	"github.com/lib/pq"
	DTO "github.com/slodkiadrianek/MINI-BUCKET/internal/bucket/DTO"
)

func TestCreate(t *testing.T) {
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
				mock.ExpectPrepare("INSERT INTO buckets").
					ExpectQuery().
					WithArgs(sqlmock.AnyArg(), sqlmock.AnyArg(), sqlmock.AnyArg(), sqlmock.AnyArg(), sqlmock.AnyArg(), sqlmock.AnyArg(), sqlmock.AnyArg()).
					WillReturnRows(sqlmock.NewRows([]string{"id"}).AddRow(1))
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
				mock.ExpectPrepare("INSERT INTO buckets").
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
				mock.ExpectPrepare("INSERT INTO buckets").ExpectQuery().
					WithArgs(sqlmock.AnyArg(), sqlmock.AnyArg(), sqlmock.AnyArg(), sqlmock.AnyArg(), sqlmock.AnyArg(), sqlmock.AnyArg(), sqlmock.AnyArg()).
					WillReturnError(&pq.Error{Code: "23505", Message: "failed to execute sql query"})
				return db, ctx
			},
			wantErr: true,
			err:     &pq.Error{Code: "23505", Message: "failed to execute sql query"},
		},

		{
			title: "context cancelled",
			setupMock: func() (*sql.DB, context.Context) {
				db, mock, _ := sqlmock.New()
				ctx, cancel := context.WithCancel(context.Background())
				cancel()
				mock.ExpectPrepare("INSERT INTO buckets").ExpectQuery().
					WithArgs(sqlmock.AnyArg(), sqlmock.AnyArg(), sqlmock.AnyArg(), sqlmock.AnyArg(), sqlmock.AnyArg(), sqlmock.AnyArg(), sqlmock.AnyArg()).
					WillReturnError(context.Canceled)
				return db, ctx
			},
			wantErr: true,
			err:     context.Canceled,
		},
	}

	for _, testScenario := range testScenarios {
		t.Run(testScenario.title, func(t *testing.T) {
			loggerService := setupBucketRepositoryDependencies()
			db, ctx := testScenario.setupMock()
			bucketRepository := NewBucketRepository(loggerService, db)
			bucketInput := DTO.BucketInput{}
			_, err := bucketRepository.Create(ctx, 1, bucketInput)
			if (err != nil) != testScenario.wantErr {
				t.Errorf("Create() error = %v, wantErr = %v", err, testScenario.wantErr)
			}

			if err != nil && testScenario.err != nil {
				if err.Error() != testScenario.err.Error() {
					t.Errorf("Create() error = %v, scenarioError = %v", err, testScenario.err)
				}
			}
		})
	}
}
