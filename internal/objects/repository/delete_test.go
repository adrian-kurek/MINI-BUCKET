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



func TestDeleteOne(t *testing.T) {
	type args struct {
		title string
		setupMock func () (*sql.DB)
		wantErr bool
		err error
	}

	testScenarios := []args{
		{
			title: "with proper data",
			setupMock: func() *sql.DB {
				db,mock,_ := sqlmock.New()
				mock.ExpectPrepare(regexp.QuoteMeta("DELETE FROM objects WHERE object_key = $1")).
				ExpectExec().
				WithArgs(sqlmock.AnyArg()).
				WillReturnResult(sqlmock.NewResult(0,1))
				return db
			},
			wantErr: false,
			err: nil,
		},
		{
			title: "failed to prepare query",
			setupMock: func() *sql.DB {
				db,mock,_ := sqlmock.New()
				mock.ExpectPrepare(regexp.QuoteMeta("DELETE FROM objects WHERE object_key = $1")).
				WillReturnError(errors.New("failed to prepare query"))
				return db
			},
			wantErr: true,
			err: errors.New("failed to prepare query"),
		},
		{
			title: "failed to execute query",
			setupMock: func() *sql.DB {
				db,mock,_ := sqlmock.New()
				mock.ExpectPrepare(regexp.QuoteMeta("DELETE FROM objects WHERE object_key = $1")).
				ExpectExec().
				WithArgs(sqlmock.AnyArg()).
				WillReturnError(errors.New("failed to execute query"))
				return db
			},
			wantErr: true,
			err: errors.New("failed to execute query"),
		},
	}


	for _, testscenario := range testScenarios {
		t.Run(testscenario.title, func(t *testing.T) {
			ctx := context.Background()
			db := testscenario.setupMock()

			loggerservice := setupObjectRepositoryDependencies()
			repo := objectRepository.New( db,loggerservice)
			err := repo.DeleteOne(ctx,"test")

			if (err != nil) != testscenario.wantErr {
				t.Errorf("DeleteOne() error = %v, wantErr = %v", err, testscenario.wantErr)
			}

			if err != nil && testscenario.err != nil {
				if err.Error() != testscenario.err.Error() {
					t.Errorf("DeleteOne() error = %v, scenarioError = %v", err, testscenario.err)
				}
			}
		})
	}
}
