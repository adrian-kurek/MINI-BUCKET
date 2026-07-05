package repository_test

import (
	"context"
	"database/sql"
	"errors"
	"log"
	"regexp"
	"testing"

	"github.com/DATA-DOG/go-sqlmock"
	"github.com/slodkiadrianek/MINI-BUCKET/internal/objects/DTO"
	objectRepository "github.com/slodkiadrianek/MINI-BUCKET/internal/objects/repository"
)


func TestUpdate(t *testing.T) {
	type args struct {
		title string
		setupMock func () (*sql.DB)
		wantErr bool
		err error
	}

	testScenarios := []args{
		{
			title: "with proper data",
			setupMock: func ()(*sql.DB) {
				db,mock,_ := sqlmock.New()
				mock.ExpectBegin()
				mock.ExpectPrepare(regexp.QuoteMeta(`UPDATE objects SET 
					size_bytes = $1,
					etag = $2,
					storage_class = $3,
					object_uuid = $4,
					updated_at = NOW() WHERE id = $5`)).
					ExpectExec().
					WithArgs(sqlmock.AnyArg(), sqlmock.AnyArg(), sqlmock.AnyArg(), sqlmock.AnyArg(), sqlmock.AnyArg()).
					WillReturnResult(sqlmock.NewResult(1, 1))
				return db
			},
			wantErr: false,
			err: nil,
		},
		{
			title: "failed to prepare query",
			setupMock: func ()(*sql.DB) {
				db,mock,_ := sqlmock.New()
				mock.ExpectBegin()
				mock.ExpectPrepare(regexp.QuoteMeta(`UPDATE objects SET 
					size_bytes = $1,
					etag = $2,
					storage_class = $3,
					object_uuid = $4,
					updated_at = NOW() WHERE id = $5`)).
					WillReturnError(errors.New("failed to prepare query"))
				return db
			},
			wantErr: true,
			err: errors.New("failed to prepare query"),
		},
		{
			title: "failed to execute query",
			setupMock: func ()(*sql.DB) {
				db,mock,_ := sqlmock.New()
				mock.ExpectBegin()
				mock.ExpectPrepare(regexp.QuoteMeta(`UPDATE objects SET 
					size_bytes = $1,
					etag = $2,
					storage_class = $3,
					object_uuid = $4,
					updated_at = NOW() WHERE id = $5`)).
					ExpectExec().
					WithArgs(sqlmock.AnyArg(), sqlmock.AnyArg(), sqlmock.AnyArg(), sqlmock.AnyArg(), sqlmock.AnyArg()).
					WillReturnError(errors.New("failed to execute query"))
				mock.ExpectRollback()
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
			tx, err := db.BeginTx(context.Background(), nil)
			if err != nil {
				panic(err)
			}
			defer func() {
				if closeErr := tx.Rollback(); closeErr != nil {
					log.Println("failed to roll back query", closeErr)
				}
			}()

			loggerservice := setupObjectRepositoryDependencies()
			repo := objectRepository.New( db,loggerservice)
			bucketInput := DTO.Update{
				SizeBytes: 1,
				ETag: "test",
				StorageClass: "STANDARD",
				UUID: "1234",
				ObjectID: 1,
			}
			err = repo.Update(ctx,tx,  bucketInput)

			if (err != nil) != testscenario.wantErr {
				t.Errorf("Update() error = %v, wantErr = %v", err, testscenario.wantErr)
			}

			if err != nil && testscenario.err != nil {
				if err.Error() != testscenario.err.Error() {
					t.Errorf("Update() error = %v, scenarioError = %v", err, testscenario.err)
				}
			}
		})
	}
}
