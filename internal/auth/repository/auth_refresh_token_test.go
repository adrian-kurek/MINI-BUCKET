package repository

import (
	"context"
	"database/sql"
	"testing"

	"github.com/DATA-DOG/go-sqlmock"
)

func TestInsertRefreshToken(t *testing.T) {
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
				mock.ExpectPrepare("INSERT INTO refresh_tokens").
					ExpectExec().
					WithArgs(sqlmock.AnyArg(), sqlmock.AnyArg(), sqlmock.AnyArg(), sqlmock.AnyArg(), sqlmock.AnyArg(), sqlmock.AnyArg()).
					WillReturnResult(sqlmock.NewResult(1, 1))

				return db, ctx
			},
			wantErr: false,
			err:     nil,
		},
	}

	for _, testScenario := range testScenarios {
		t.Run(testScenario.title, func(t *testing.T) {
			db, ctx := testScenario.setupMock()
			loggerService := setupAuthRepositoryDependencies()
			authRepository := NewAuthRepository(loggerService, db)
			err := authRepository.InsertRefreshToken(ctx, "192.168.0.1", "chrome", "eyJ0eXAiOiJKV1QiLCJhbGciOiJIUzI1NiJ9.eyJpbnN0cnVjdG9yTlIiOiItIiwiZXhwIjoxNzc5MDI2ODg4fQ.EMN_WVoAKPq0ocqd9AsAKcXE3RRCpk6erPZhBuiNP68", 1)

			if (err != nil) != testScenario.wantErr {
				t.Errorf("InsertRefreshToken() error = %v, wantErr = %v", err, testScenario.wantErr)
			}

			if err != nil && testScenario.err != nil {
				if err.Error() != testScenario.err.Error() {
					t.Errorf("InsertRefreshToken() error = %v, scenarioError = %v", err, testScenario.err)
				}
			}
		})
	}
}
