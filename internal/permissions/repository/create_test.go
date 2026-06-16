package repository

import (
	"context"
	"database/sql"
	"errors"
	"testing"

	"github.com/DATA-DOG/go-sqlmock"
	"github.com/lib/pq"
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
				mock.ExpectPrepare("INSERT INTO bucket_permissions").
					ExpectQuery().
					WithArgs(sqlmock.AnyArg(), sqlmock.AnyArg(), sqlmock.AnyArg()).
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
				mock.ExpectPrepare("INSERT INTO bucket_permissions").
					WillReturnError(errors.New("failed to prepare sql query"))
				return db, ctx
			},
			wantErr: true,
			err:     errors.New("failed to prepare sql query"),
		},
		{
			title: "duplicate permission",
			setupMock: func() (*sql.DB, context.Context) {
				db, mock, _ := sqlmock.New()
				ctx := context.Background()
				mock.ExpectPrepare("INSERT INTO bucket_permissions").
					ExpectQuery().WithArgs(sqlmock.AnyArg(), sqlmock.AnyArg(), sqlmock.AnyArg()).
					WillReturnError(&pq.Error{Code: "23505", Message: "duplicate key value"})
				return db, ctx
			},
			wantErr: true,
			err:     &pq.Error{Code: "23505", Message: "duplicate key value"},
		},

		{
			title: "context cancelled",
			setupMock: func() (*sql.DB, context.Context) {
				db, mock, _ := sqlmock.New()
				ctx, cancel := context.WithCancel(context.Background())
				cancel()
				mock.ExpectPrepare("INSERT INTO bucket_permissions").
					ExpectExec().WithArgs(sqlmock.AnyArg(), sqlmock.AnyArg(), sqlmock.AnyArg(), sqlmock.AnyArg()).
					WillReturnError(context.Canceled)
				return db, ctx
			},
			wantErr: true,
			err:     context.Canceled,
		},
	}

	for _, testScenario := range testScenarios {
		t.Run(testScenario.title, func(t *testing.T) {
			loggerService := setupPermissionsRepositoryDependencies()
			db, ctx := testScenario.setupMock()
			permissionRepository := NewPermissionRepository(loggerService, db)
			_, err := permissionRepository.Create(ctx, 1, 1, 7)
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
