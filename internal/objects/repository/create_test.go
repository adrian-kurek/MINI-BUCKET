package repository_test

import (
	"context"
	"database/sql"
	"errors"
	"testing"

	"github.com/DATA-DOG/go-sqlmock"
	"github.com/lib/pq"
	DTO "github.com/slodkiadrianek/MINI-BUCKET/internal/objects/DTO"
	objectRepository "github.com/slodkiadrianek/MINI-BUCKET/internal/objects/repository"
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
				mock.ExpectBegin()
				mock.ExpectPrepare("INSERT INTO objects").
					ExpectQuery().
					WithArgs(sqlmock.AnyArg(), sqlmock.AnyArg(), sqlmock.AnyArg(), sqlmock.AnyArg(), sqlmock.AnyArg(), sqlmock.AnyArg(), sqlmock.AnyArg()).
					WillReturnRows(sqlmock.NewRows([]string{"id"}).AddRow(1))
				mock.ExpectCommit()
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
				mock.ExpectBegin()
				mock.ExpectPrepare("INSERT INTO objects").
					WillReturnError(errors.New("failed to prepare sql query"))
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
				mock.ExpectPrepare("INSERT INTO objects").ExpectQuery().
					WithArgs(sqlmock.AnyArg(), sqlmock.AnyArg(), sqlmock.AnyArg(), sqlmock.AnyArg(), sqlmock.AnyArg(), sqlmock.AnyArg(), sqlmock.AnyArg()).
					WillReturnError(&pq.Error{Code: "23505", Message: "failed to execute sql query"})
				mock.ExpectRollback()
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
				mock.ExpectBegin()
				mock.ExpectPrepare("INSERT INTO objects").ExpectQuery().
					WithArgs(sqlmock.AnyArg(), sqlmock.AnyArg(), sqlmock.AnyArg(), sqlmock.AnyArg(), sqlmock.AnyArg(), sqlmock.AnyArg(), sqlmock.AnyArg()).
					WillReturnError(context.Canceled)
				mock.ExpectRollback()
				return db, ctx
			},
			wantErr: true,
			err:     context.Canceled,
		},
	}

	for _, testScenario := range testScenarios {
		t.Run(testScenario.title, func(t *testing.T) {
			loggerService := setupObjectRepositoryDependencies()
			db, ctx := testScenario.setupMock()
			objectRepository := objectRepository.NewObjectRepository(db, loggerService)
			tx, err := db.BeginTx(context.Background(), nil)
			if err != nil {
				panic(err)
			}
			defer tx.Rollback()

			_, err = objectRepository.Create(ctx, tx, DTO.Create{})
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
