package repository_test

import (
	"context"
	"database/sql"
	"errors"
	"regexp"

	"testing"

	"github.com/DATA-DOG/go-sqlmock"
	versionRepository "github.com/slodkiadrianek/MINI-BUCKET/internal/versions/repository"
)


func TestDelete(t *testing.T) {
	type args struct {
		title     string
		setupMock func() *sql.DB
		wantErr   bool
		err       error
	}

	testScenarios := []args{
		{
			title: "with proper data",
			setupMock: func() *sql.DB {
				db,mock,_ := sqlmock.New()
				mock.ExpectPrepare(regexp.QuoteMeta("DELETE FROM object_versions WHERE id = $1")).
				ExpectExec().
				WithArgs(sqlmock.AnyArg()).
				WillReturnResult(sqlmock.NewResult(0,1))

				return db
			},
			wantErr: false,
			err: nil,
		},
		{
			title: "failed to execute query",
			setupMock: func() *sql.DB {
				db,mock,_ := sqlmock.New()
				mock.ExpectPrepare(regexp.QuoteMeta("DELETE FROM object_versions WHERE id = $1")).
				ExpectExec().
				WithArgs(sqlmock.AnyArg()).
				WillReturnError(errors.New("failed to execute query"))

				return db
			},
			wantErr: true,
			err: errors.New("failed to execute query"),
		},
		{
			title: "failed to prepare query",
			setupMock: func() *sql.DB {
				db,mock,_ := sqlmock.New()
				mock.ExpectPrepare(regexp.QuoteMeta("DELETE FROM object_versions WHERE id = $1")).
				WillReturnError(errors.New("failed to prepare query"))

				return db
			},
			wantErr: true,
			err: errors.New("failed to prepare query"),
		},
	}

	for _, testScenario := range testScenarios {
		t.Run(testScenario.title, func(t *testing.T) {
			loggerService := setupVersionRepositoryDependencies()
			ctx := context.Background()
			db := testScenario.setupMock()
			repo := versionRepository.New(db, loggerService)

			 err := repo.Delete(ctx, 1)
			if (err != nil) != testScenario.wantErr {
				t.Errorf("Delete() error = %v, wantErr = %v", err, testScenario.wantErr)
			}

			if err != nil && testScenario.err != nil {
				if err.Error() != testScenario.err.Error() {
					t.Errorf("Delete() error = %v, scenarioError = %v", err, testScenario.err)
				}
			}
		})
	}
}
