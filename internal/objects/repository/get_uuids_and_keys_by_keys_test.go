package repository_test

import (
	"context"
	"database/sql"
	"errors"
	"fmt"
	"regexp"
	"testing"

	"github.com/DATA-DOG/go-sqlmock"
	objectRepository "github.com/slodkiadrianek/MINI-BUCKET/internal/objects/repository"
)

func TestGetUUIDsAdKesByKeys(t *testing.T) {
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
				placeholders := "$1"
				expectedQuery := fmt.Sprintf(
					`SELECT o.object_key,o.object_uuid FROM objects o 
						WHERE o.object_key IN ( %s) AND o.bucket_id = $%d`,
					placeholders, 2,
				)
				db, mock, _ := sqlmock.New()
				mock.ExpectPrepare(
					regexp.QuoteMeta(expectedQuery),
				).
					ExpectQuery().
					WithArgs(sqlmock.AnyArg(), sqlmock.AnyArg()).
					WillReturnRows(sqlmock.NewRows([]string{"object_key", "object_uuid"}).AddRow("test", "12324"))
				return db
			},
			wantErr: false,
			err:     nil,
		},
		{
			title: "row error",
			setupMock: func() *sql.DB {
				placeholders := "$1"
				expectedQuery := fmt.Sprintf(
					`SELECT o.object_key,o.object_uuid FROM objects o 
						WHERE o.object_key IN ( %s) AND o.bucket_id = $%d`,
					placeholders, 2,
				)
				db, mock, _ := sqlmock.New()
				mock.ExpectPrepare(
					regexp.QuoteMeta(expectedQuery),
				).
					ExpectQuery().
					WithArgs(sqlmock.AnyArg(), sqlmock.AnyArg()).
					WillReturnRows(
						sqlmock.NewRows([]string{"object_key", "object_uuid"}).
							AddRow("test", "12324").
							RowError(0, errors.New("scan failed")),
					)
				return db
			},
			wantErr: true,
			err:     errors.New("scan failed"),
		},
		{
			title: "failed to prepare query",
			setupMock: func() *sql.DB {
				placeholders := "$1"
				expectedQuery := fmt.Sprintf(
					`SELECT o.object_key,o.object_uuid FROM objects o 
						WHERE o.object_key IN ( %s) AND o.bucket_id = $%d`,
					placeholders, 2,
				)
				db, mock, _ := sqlmock.New()
				mock.ExpectPrepare(
					regexp.QuoteMeta(expectedQuery),
				).
					WillReturnError(errors.New("failed to prepare query"))
				return db
			},
			wantErr: true,
			err:     errors.New("failed to prepare query"),
		},
		{
			title: "failed to execute query",
			setupMock: func() *sql.DB {
				placeholders := "$1"
				expectedQuery := fmt.Sprintf(
					`SELECT o.object_key,o.object_uuid FROM objects o 
						WHERE o.object_key IN ( %s) AND o.bucket_id = $%d`,
					placeholders, 2,
				)
				db, mock, _ := sqlmock.New()
				mock.ExpectPrepare(
					regexp.QuoteMeta(expectedQuery),
				).
					ExpectQuery().
					WithArgs(sqlmock.AnyArg(), sqlmock.AnyArg()).
					WillReturnError(errors.New("failed to execute query"))
				return db
			},
			wantErr: true,
			err:     errors.New("failed to execute query"),
		},
		{
			title: "failed to find an object",
			setupMock: func() *sql.DB {
				placeholders := "$1"
				expectedQuery := fmt.Sprintf(
					`SELECT o.object_key,o.object_uuid FROM objects o 
						WHERE o.object_key IN ( %s) AND o.bucket_id = $%d`,
					placeholders, 2,
				)
				db, mock, _ := sqlmock.New()
				mock.ExpectPrepare(
					regexp.QuoteMeta(expectedQuery),
				).
					ExpectQuery().
					WithArgs(sqlmock.AnyArg(), sqlmock.AnyArg()).
					WillReturnRows(sqlmock.NewRows([]string{"object_key", "object_uuid"}))
				return db
			},
			wantErr: true,
			err:     errors.New("api error: "),
		},
	}

	for _, testscenario := range testScenarios {
		t.Run(testscenario.title, func(t *testing.T) {
			ctx := context.Background()
			db := testscenario.setupMock()

			loggerservice := setupObjectRepositoryDependencies()
			repo := objectRepository.New(db, loggerservice)
			_, err := repo.GetUUIDsAndKeysByKeys(ctx, 1, []string{"test"})

			if (err != nil) != testscenario.wantErr {
				t.Errorf("GetUUIDsAndKeysByKeys() error = %v, wantErr = %v", err, testscenario.wantErr)
			}

			if err != nil && testscenario.err != nil {
				if err.Error() != testscenario.err.Error() {
					t.Errorf("GetUUIDsAndKeysByKeys() error = %v, scenarioError = %v", err, testscenario.err)
				}
			}
		})
	}
}
