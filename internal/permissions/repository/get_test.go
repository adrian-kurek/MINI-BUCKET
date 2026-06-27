package repository_test

import (
	"context"
	"database/sql"
	"errors"
	"regexp"
	"testing"

	"github.com/DATA-DOG/go-sqlmock"
	permissionRepository "github.com/slodkiadrianek/MINI-BUCKET/internal/permissions/repository"
)

func TestGetPermissionValByUserID(t *testing.T) {
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
						SELECT 
							id,
							permission 
						FROM bucket_permissions 
						WHERE bucket_id = $1 AND user_id = $2`,
					),
				).
					ExpectQuery().
					WithArgs(sqlmock.AnyArg(), sqlmock.AnyArg()).
					WillReturnRows(
						sqlmock.NewRows(
							[]string{"id", "permission"},
						).AddRow(
							1,
							7,
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
						SELECT 
							id,
							permission 
						FROM bucket_permissions 
						WHERE bucket_id = $1 AND user_id = $2`,
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
						SELECT 
							id,
							permission 
						FROM bucket_permissions 
						WHERE bucket_id = $1 AND user_id = $2`,
					),
				).ExpectQuery().
					WithArgs(sqlmock.AnyArg(), sqlmock.AnyArg()).WillReturnError(errors.New("failed to execute sql query"))

				return db, ctx
			},
			wantErr: true,
			err:     errors.New("failed to execute sql query"),
		},
		{
			title: "permission not found",
			setupMock: func() (*sql.DB, context.Context) {
				db, mock, _ := sqlmock.New()
				ctx := context.Background()
				mock.ExpectPrepare(
					regexp.QuoteMeta(`
						SELECT 
							id,
							permission 
						FROM bucket_permissions 
						WHERE bucket_id = $1 AND user_id = $2`,
					),
				).ExpectQuery().
					WithArgs(sqlmock.AnyArg(), sqlmock.AnyArg()).WillReturnError(sql.ErrNoRows)

				return db, ctx
			},
			wantErr: true,
			err:     sql.ErrNoRows,
		},
	}

	for _, testScenario := range testScenarios {
		t.Run(testScenario.title, func(t *testing.T) {
			db, ctx := testScenario.setupMock()
			loggerService := setupPermissionsRepositoryDependencies()
			permissionRepository := permissionRepository.NewPermissionRepository(loggerService, db)
			_, err := permissionRepository.GetPermissionValByUserID(ctx, 1, 1)

			if (err != nil) != testScenario.wantErr {
				t.Errorf("GetPermissionValByUserID() error = %v, wantErr = %v", err, testScenario.wantErr)
			}

			if err != nil && testScenario.err != nil {
				if err.Error() != testScenario.err.Error() {
					t.Errorf("GetPermissionValByUserID() error = %v, scenarioError = %v", err, testScenario.err)
				}
			}
		})
	}
}
