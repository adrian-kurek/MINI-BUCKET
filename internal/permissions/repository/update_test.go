package repository

import (
	"context"
	"database/sql"
	"errors"
	"regexp"
	"testing"

	"github.com/DATA-DOG/go-sqlmock"
)

func TestUpdate(t *testing.T) {
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
				mock.ExpectPrepare(regexp.QuoteMeta("UPDATE bucket_permissions SET permission = $1 WHERE id = $2 AND bucket_id = $3 AND user_id = $4")).
					ExpectExec().
					WithArgs(sqlmock.AnyArg(), sqlmock.AnyArg(), sqlmock.AnyArg(), sqlmock.AnyArg()).
					WillReturnResult(sqlmock.NewResult(1, 1))

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
				mock.ExpectPrepare(regexp.QuoteMeta("UPDATE bucket_permissions SET permission = $1 WHERE id = $2 AND bucket_id = $3 AND user_id = $4")).
					WillReturnError(errors.New("failed to prepare sql query"))

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
				mock.ExpectPrepare(regexp.QuoteMeta("UPDATE bucket_permissions SET permission = $1 WHERE id = $2 AND bucket_id = $3 AND user_id = $4")).
					ExpectExec().
					WithArgs(sqlmock.AnyArg(), sqlmock.AnyArg(), sqlmock.AnyArg(), sqlmock.AnyArg()).
					WillReturnError(errors.New("failed to execute sql query"))

				return db, ctx
			},
			wantErr: true,
			err:     errors.New("failed to execute sql query"),
		},
	}

	for _, testscenario := range testScenarios {
		t.Run(testscenario.title, func(t *testing.T) {
			db, ctx := testscenario.setupMock()
			loggerservice := setupPermissionsRepositoryDependencies()
			permissionRepository := NewPermissionRepository(loggerservice, db)
			err := permissionRepository.Update(ctx, 1, 1, 1, 7)

			if (err != nil) != testscenario.wantErr {
				t.Errorf("Update() error = %v, wanterr = %v", err, testscenario.wantErr)
			}

			if err != nil && testscenario.err != nil {
				if err.Error() != testscenario.err.Error() {
					t.Errorf("Update() error = %v, scenarioerror = %v", err, testscenario.err)
				}
			}
		})
	}
}
