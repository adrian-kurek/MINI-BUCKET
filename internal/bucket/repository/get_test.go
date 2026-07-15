package repository_test

import (
	"context"
	"database/sql"
	"errors"
	"regexp"
	"testing"

	"github.com/DATA-DOG/go-sqlmock"
	bucketRepository "github.com/slodkiadrianek/MINI-BUCKET/internal/bucket/repository"
)

func TestGetPrivacyInfo(t *testing.T) {
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
				db, mock, _ := sqlmock.New()
				mock.ExpectPrepare(regexp.QuoteMeta("SELECT public_access FROM buckets WHERE id = $1")).
					ExpectQuery().
					WithArgs(sqlmock.AnyArg()).
					WillReturnRows(sqlmock.NewRows([]string{"public_access"}).AddRow(true))
				return db
			},
			wantErr: false,
			err:     nil,
		},

		{
			title: "prepare query failed",
			setupMock: func() *sql.DB {
				db, mock, _ := sqlmock.New()
				mock.ExpectPrepare(regexp.QuoteMeta("SELECT public_access FROM buckets WHERE id = $1")).
					WillReturnError(errors.New("failed to prepare sql query"))

				return db
			},
			wantErr: true,
			err:     errors.New("failed to prepare sql query"),
		},
		{
			title: "no rows",
			setupMock: func() *sql.DB {
				db, mock, _ := sqlmock.New()
				mock.ExpectPrepare(regexp.QuoteMeta("SELECT public_access FROM buckets WHERE id = $1")).
					ExpectQuery().
					WithArgs(sqlmock.AnyArg()).
					WillReturnError(sql.ErrNoRows)

				return db
			},
			wantErr: true,
			err:     errors.New("api error: "),
		},
		{
			title: "execute query failed",
			setupMock: func() *sql.DB {
				db, mock, _ := sqlmock.New()
				mock.ExpectPrepare(regexp.QuoteMeta("SELECT public_access FROM buckets WHERE id = $1")).
					ExpectQuery().
					WithArgs(sqlmock.AnyArg()).
					WillReturnError(errors.New("failed to execute sql query"))

				return db
			},
			wantErr: true,
			err:     errors.New("failed to execute sql query"),
		},
	}

	for _, testscenario := range testScenarios {
		t.Run(testscenario.title, func(t *testing.T) {
			ctx := context.Background()
			db := testscenario.setupMock()
			loggerservice := setupBucketRepositoryDependencies()
			repo := bucketRepository.New(loggerservice, db)
			_, err := repo.GetPrivacyInfo(ctx, 1)

			if (err != nil) != testscenario.wantErr {
				t.Errorf("GetPrivacyInfo() error = %v, wantErr = %v", err, testscenario.wantErr)
			}

			if err != nil && testscenario.err != nil {
				if err.Error() != testscenario.err.Error() {
					t.Errorf("GetPrivacyInfo() error = %v, scenarioError = %v", err, testscenario.err)
				}
			}
		})
	}
}

func TestIsVersioningEnabled(t *testing.T) {
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
				db, mock, _ := sqlmock.New()
				mock.ExpectPrepare(regexp.QuoteMeta("SELECT versioning_enabled FROM buckets WHERE id = $1")).
					ExpectQuery().
					WithArgs(sqlmock.AnyArg()).
					WillReturnRows(sqlmock.NewRows([]string{"versioning_enabled"}).AddRow(true))
				return db
			},
			wantErr: false,
			err:     nil,
		},

		{
			title: "prepare query failed",
			setupMock: func() *sql.DB {
				db, mock, _ := sqlmock.New()
				mock.ExpectPrepare(regexp.QuoteMeta("SELECT versioning_enabled FROM buckets WHERE id = $1")).
					WillReturnError(errors.New("failed to prepare sql query"))

				return db
			},
			wantErr: true,
			err:     errors.New("failed to prepare sql query"),
		},
		{
			title: "no rows",
			setupMock: func() *sql.DB {
				db, mock, _ := sqlmock.New()
				mock.ExpectPrepare(regexp.QuoteMeta("SELECT versioning_enabled FROM buckets WHERE id = $1")).
					ExpectQuery().
					WithArgs(sqlmock.AnyArg()).
					WillReturnError(sql.ErrNoRows)

				return db
			},
			wantErr: true,
			err:     errors.New("api error: "),
		},
		{
			title: "execute query failed",
			setupMock: func() *sql.DB {
				db, mock, _ := sqlmock.New()
				mock.ExpectPrepare(regexp.QuoteMeta("SELECT versioning_enabled FROM buckets WHERE id = $1")).
					ExpectQuery().
					WithArgs(sqlmock.AnyArg()).
					WillReturnError(errors.New("failed to execute sql query"))

				return db
			},
			wantErr: true,
			err:     errors.New("failed to execute sql query"),
		},
	}

	for _, testscenario := range testScenarios {
		t.Run(testscenario.title, func(t *testing.T) {
			ctx := context.Background()
			db := testscenario.setupMock()
			loggerservice := setupBucketRepositoryDependencies()
			repo := bucketRepository.New(loggerservice, db)
			_, err := repo.IsVersioningEnabled(ctx, 1)

			if (err != nil) != testscenario.wantErr {
				t.Errorf("IsVersioningEnabled() error = %v, wantErr = %v", err, testscenario.wantErr)
			}

			if err != nil && testscenario.err != nil {
				if err.Error() != testscenario.err.Error() {
					t.Errorf("IsVersioningEnabled() error = %v, scenarioError = %v", err, testscenario.err)
				}
			}
		})
	}
}
