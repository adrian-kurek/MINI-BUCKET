package repository

import (
	"context"
	"database/sql"
	"errors"
	"regexp"
	"testing"

	"github.com/DATA-DOG/go-sqlmock"
	dto "github.com/slodkiadrianek/MINI-BUCKET/internal/bucket/DTO"
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
				mock.ExpectPrepare(regexp.QuoteMeta("UPDATE buckets SET name = $1,versioning_enabled = $2, public_access = $3, storage_class = $4, encryption_enabled = $5, updated_at = NOW() WHERE id = $6 AND owner_id = $7")).
					ExpectExec().
					WithArgs(sqlmock.AnyArg(), sqlmock.AnyArg(), sqlmock.AnyArg(), sqlmock.AnyArg(), sqlmock.AnyArg(), sqlmock.AnyArg(), sqlmock.AnyArg()).
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
				mock.ExpectPrepare(regexp.QuoteMeta("UPDATE buckets SET name = $1,versioning_enabled = $2, public_access = $3, storage_class = $4, encryption_enabled = $5, updated_at = NOW() WHERE id = $6 AND owner_id = $7")).
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
				mock.ExpectPrepare(regexp.QuoteMeta("UPDATE buckets SET name = $1,versioning_enabled = $2, public_access = $3, storage_class = $4, encryption_enabled = $5, updated_at = NOW() WHERE id = $6 AND owner_id = $7")).
					ExpectExec().
					WithArgs(sqlmock.AnyArg(), sqlmock.AnyArg(), sqlmock.AnyArg(), sqlmock.AnyArg(), sqlmock.AnyArg(), sqlmock.AnyArg(), sqlmock.AnyArg()).
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
			loggerservice := setupBucketRepositoryDependencies()
			bucketRepository := NewBucketRepository(loggerservice, db)
			bucketInput := dto.BucketInput{}
			err := bucketRepository.Update(ctx, 1, 1, bucketInput)

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
