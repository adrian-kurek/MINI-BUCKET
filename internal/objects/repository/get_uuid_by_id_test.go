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



func TestGetUUIDByID(t *testing.T) {
	type args struct {
		title string
		setupMock func () (*sql.DB)
		wantErr bool
		err error	
	}

	testScenarios := []args{
		{
			title: "with proper data",
			setupMock: func () (*sql.DB) {
				db,mock,_ := sqlmock.New()
				mock.ExpectPrepare(
					regexp.QuoteMeta("SELECT object_uuid FROM objects WHERE object_key = $1 AND bucket_id = $2"),
				).
				ExpectQuery().
				WithArgs(sqlmock.AnyArg(), sqlmock.AnyArg()).
				WillReturnRows(sqlmock.NewRows([]string{"object_uuid"}).AddRow("12324"))
				return db
			},
			wantErr: false,
			err: nil,
		},
		{
			title: "failed to prepare query",
			setupMock: func () (*sql.DB) {
				db,mock,_ := sqlmock.New()
				mock.ExpectPrepare(
					regexp.QuoteMeta("SELECT object_uuid FROM objects WHERE object_key = $1 AND bucket_id = $2"),
				).
				WillReturnError(errors.New("failed to prepare query"))
				return db
			},
			wantErr: true,
			err: errors.New("failed to prepare query"),
		},
		{
			title: "failed to execute query",
			setupMock: func () (*sql.DB) {
				db,mock,_ := sqlmock.New()
				mock.ExpectPrepare(
					regexp.QuoteMeta("SELECT object_uuid FROM objects WHERE object_key = $1 AND bucket_id = $2"),
				).
				ExpectQuery().
				WithArgs(sqlmock.AnyArg(), sqlmock.AnyArg()).
				WillReturnError(errors.New("failed to execute query"))
				return db
			},
			wantErr: true,
			err: errors.New("failed to execute query"),
		},
		{
			title: "failed to find an object",
			setupMock: func () (*sql.DB) {
				db,mock,_ := sqlmock.New()
				mock.ExpectPrepare(
					regexp.QuoteMeta("SELECT object_uuid FROM objects WHERE object_key = $1 AND bucket_id = $2"),
				).
				ExpectQuery().
				WithArgs(sqlmock.AnyArg(), sqlmock.AnyArg()).
				WillReturnError(sql.ErrNoRows)
				return db
			},
			wantErr: true,
			err: errors.New("api error: failed to find object with provided objectKey and bucketID"),
		},
	}

	for _, testscenario := range testScenarios {
		t.Run(testscenario.title, func(t *testing.T) {
			ctx := context.Background()
			db := testscenario.setupMock()

			loggerservice := setupObjectRepositoryDependencies()
			repo := objectRepository.New( db,loggerservice)
			_,err := repo.GetUUIDByID(ctx,"test",1)

			if (err != nil) != testscenario.wantErr {
				t.Errorf("GetUUIDByID() error = %v, wantErr = %v", err, testscenario.wantErr)
			}

			if err != nil && testscenario.err != nil {
				if err.Error() != testscenario.err.Error() {
					t.Errorf("GetUUIDByID() error = %v, scenarioError = %v", err, testscenario.err)
				}
			}
		})
	}
}
