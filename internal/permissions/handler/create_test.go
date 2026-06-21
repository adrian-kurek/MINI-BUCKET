package handler

import (
	"bytes"
	"context"
	"errors"
	"net/http"
	"net/http/httptest"
	"testing"

	commonInterfaces "github.com/slodkiadrianek/MINI-BUCKET/common/interfaces"
	jsonutil "github.com/slodkiadrianek/MINI-BUCKET/common/json_util"
	"github.com/slodkiadrianek/MINI-BUCKET/common/request"
	DTO "github.com/slodkiadrianek/MINI-BUCKET/internal/permissions/DTO"
	authMocks "github.com/slodkiadrianek/MINI-BUCKET/test/mocks/auth"
	permissionMocks "github.com/slodkiadrianek/MINI-BUCKET/test/mocks/permissions"
	"github.com/stretchr/testify/mock"
)

func TestCreate(t *testing.T) {
	type args struct {
		title           string
		bodyRequestData DTO.Upsert
		verifiedUser    bool
		withBucketID    bool
		setupMock       func() (permissionService, commonInterfaces.AuthenticationMiddleware, http.ResponseWriter)
		wantErr         bool
		err             error
	}

	testScenarios := []args{
		{
			title: "with proper data",
			bodyRequestData: DTO.Upsert{
				UserID:     1,
				Permission: 7,
			},
			verifiedUser: true,
			withBucketID: true,
			setupMock: func() (permissionService, commonInterfaces.AuthenticationMiddleware, http.ResponseWriter) {
				mPermissionService := new(permissionMocks.MockPermissionService)
				mPermissionService.On("Create", mock.Anything, mock.Anything, mock.Anything, mock.Anything, mock.Anything).Return(nil)
				mAuthenticationMiddleware := new(authMocks.MockAuthenticationMiddleware)
				r, err := http.NewRequest("POST", "/buckets/1/permissions", nil)
				if err != nil {
					panic(err)
				}
				mAuthenticationMiddleware.On("VerifyToken", mock.Anything).Return(r, context.DeadlineExceeded)
				return mPermissionService, mAuthenticationMiddleware, httptest.NewRecorder()
			},
			wantErr: false,
			err:     nil,
		},

		{
			title: "lack of userID",
			bodyRequestData: DTO.Upsert{
				Permission: 7,
			},
			verifiedUser: true,
			withBucketID: false,
			setupMock: func() (permissionService, commonInterfaces.AuthenticationMiddleware, http.ResponseWriter) {
				mPermissionService := new(permissionMocks.MockPermissionService)
				mAuthenticationMiddleware := new(authMocks.MockAuthenticationMiddleware)
				r, err := http.NewRequest("POST", "/buckets/1/permissions", nil)
				if err != nil {
					panic(err)
				}
				mAuthenticationMiddleware.On("VerifyToken", mock.Anything).Return(r, context.DeadlineExceeded)
				return mPermissionService, mAuthenticationMiddleware, httptest.NewRecorder()
			},
			wantErr: true,
			err:     errors.New("api error: the UserID field is required"),
		},

		{
			title: "failed to read user id from context",
			bodyRequestData: DTO.Upsert{
				UserID:     1,
				Permission: 7,
			},
			verifiedUser: false,
			withBucketID: false,
			setupMock: func() (permissionService, commonInterfaces.AuthenticationMiddleware, http.ResponseWriter) {
				mPermissionService := new(permissionMocks.MockPermissionService)
				mAuthenticationMiddleware := new(authMocks.MockAuthenticationMiddleware)
				r, err := http.NewRequest("POST", "/buckets/1/permissions", nil)
				if err != nil {
					panic(err)
				}
				mAuthenticationMiddleware.On("VerifyToken", mock.Anything).Return(r, context.DeadlineExceeded)
				return mPermissionService, mAuthenticationMiddleware, httptest.NewRecorder()
			},
			wantErr: true,
			err:     errors.New("failed to read user from context"),
		},

		{
			title: "lack of bucketID",
			bodyRequestData: DTO.Upsert{
				UserID:     1,
				Permission: 7,
			},
			verifiedUser: true,
			withBucketID: false,
			setupMock: func() (permissionService, commonInterfaces.AuthenticationMiddleware, http.ResponseWriter) {
				mPermissionService := new(permissionMocks.MockPermissionService)
				mAuthenticationMiddleware := new(authMocks.MockAuthenticationMiddleware)
				r, err := http.NewRequest("POST", "/buckets/1/permissions", nil)
				if err != nil {
					panic(err)
				}
				mAuthenticationMiddleware.On("VerifyToken", mock.Anything).Return(r, context.DeadlineExceeded)
				return mPermissionService, mAuthenticationMiddleware, httptest.NewRecorder()
			},
			wantErr: true,
			err:     errors.New(`strconv.Atoi: parsing "": invalid syntax`),
		},

		{
			title: "failed to create permission",
			bodyRequestData: DTO.Upsert{
				UserID:     1,
				Permission: 7,
			},
			verifiedUser: true,
			withBucketID: true,
			setupMock: func() (permissionService, commonInterfaces.AuthenticationMiddleware, http.ResponseWriter) {
				mPermissionService := new(permissionMocks.MockPermissionService)
				mPermissionService.On("Create", mock.Anything, mock.Anything, mock.Anything, mock.Anything, mock.Anything).Return(errors.New("failed to create new permission"))
				mAuthenticationMiddleware := new(authMocks.MockAuthenticationMiddleware)
				r, err := http.NewRequest("POST", "/buckets/1/permissions", nil)
				if err != nil {
					panic(err)
				}
				mAuthenticationMiddleware.On("VerifyToken", mock.Anything).Return(r, context.DeadlineExceeded)
				return mPermissionService, mAuthenticationMiddleware, httptest.NewRecorder()
			},
			wantErr: true,
			err:     errors.New(`failed to create new permission`),
		},
	}

	for _, testScenario := range testScenarios {
		t.Run(testScenario.title, func(t *testing.T) {
			loggerService := setupPermissionsHandlerDependencies()
			permissionService, authorizationMiddleware, w := testScenario.setupMock()
			permissionHandler := NewPermissionHandler(permissionService, authorizationMiddleware, loggerService)

			bodyBytes, err := jsonutil.MarshalData(testScenario.bodyRequestData)
			if err != nil {
				panic(err)
			}

			bodyReader := bytes.NewReader(bodyBytes)
			r, err := http.NewRequest("POST", "/buckets/1/permissions", bodyReader)
			if err != nil {
				panic(err)
			}
			if testScenario.withBucketID {
				r.SetPathValue("bucketID", "1")
			}
			if testScenario.verifiedUser {
				r = request.SetContext(r, "id", 1)
			}

			err = permissionHandler.Create(w, r)

			if (err != nil) != testScenario.wantErr {
				t.Errorf("Create() err = %v, wantErr = %v", err, testScenario.wantErr)
			}

			if err != nil && testScenario.err != nil {
				if err.Error() != testScenario.err.Error() {
					t.Errorf("Create() error = %v, scenarioError = %v", err, testScenario.err)
				}
			}
		})
	}
}
