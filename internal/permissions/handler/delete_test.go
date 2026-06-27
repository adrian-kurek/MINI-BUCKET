package handler_test

import (
	"bytes"
	"errors"
	"net/http"
	"net/http/httptest"
	"testing"

	commonInterfaces "github.com/slodkiadrianek/MINI-BUCKET/common/interfaces"
	jsonutil "github.com/slodkiadrianek/MINI-BUCKET/common/json_util"
	"github.com/slodkiadrianek/MINI-BUCKET/common/request"
	DTO "github.com/slodkiadrianek/MINI-BUCKET/internal/permissions/DTO"
	permissionHandler "github.com/slodkiadrianek/MINI-BUCKET/internal/permissions/handler"
	authMocks "github.com/slodkiadrianek/MINI-BUCKET/test/mocks/auth"
	permissionMocks "github.com/slodkiadrianek/MINI-BUCKET/test/mocks/permissions"
	"github.com/stretchr/testify/mock"
)

func TestDelete(t *testing.T) {
	type args struct {
		title            string
		bodyRequestData  DTO.Delete
		verifiedUser     bool
		withBucketID     bool
		withPermissionID bool
		setupMock        func(r *http.Request) (permissionHandler.PermissionService, commonInterfaces.AuthenticationMiddleware, http.ResponseWriter)
		wantErr          bool
		err              error
	}

	testScenarios := []args{
		{
			title: "with proper data",
			bodyRequestData: DTO.Delete{
				UserID: 1,
			},
			verifiedUser:     true,
			withBucketID:     true,
			withPermissionID: true,
			setupMock: func(r *http.Request) (permissionHandler.PermissionService, commonInterfaces.AuthenticationMiddleware, http.ResponseWriter) {
				mPermissionService := new(permissionMocks.MockPermissionService)
				mPermissionService.On("Delete", mock.Anything, mock.Anything, mock.Anything, mock.Anything, mock.Anything).Return(nil)
				mAuthenticationMiddleware := new(authMocks.MockAuthenticationMiddleware)
				mAuthenticationMiddleware.On("VerifyToken", mock.Anything).Return(r, nil)
				return mPermissionService, mAuthenticationMiddleware, httptest.NewRecorder()
			},
			wantErr: false,
			err:     nil,
		},

		{
			title:           "lack of userID",
			bodyRequestData: DTO.Delete{},
			verifiedUser:    true,
			withBucketID:    false,
			setupMock: func(r *http.Request) (permissionHandler.PermissionService, commonInterfaces.AuthenticationMiddleware, http.ResponseWriter) {
				mPermissionService := new(permissionMocks.MockPermissionService)
				mAuthenticationMiddleware := new(authMocks.MockAuthenticationMiddleware)
				mAuthenticationMiddleware.On("VerifyToken", mock.Anything).Return(r, nil)
				return mPermissionService, mAuthenticationMiddleware, httptest.NewRecorder()
			},
			wantErr: true,
			err:     errors.New("api error: the UserID field is required"),
		},

		{
			title: "failed to read user id from context",
			bodyRequestData: DTO.Delete{
				UserID: 1,
			},
			verifiedUser: false,
			withBucketID: false,
			setupMock: func(r *http.Request) (permissionHandler.PermissionService, commonInterfaces.AuthenticationMiddleware, http.ResponseWriter) {
				mPermissionService := new(permissionMocks.MockPermissionService)
				mAuthenticationMiddleware := new(authMocks.MockAuthenticationMiddleware)
				mAuthenticationMiddleware.On("VerifyToken", mock.Anything).Return(r, nil)
				return mPermissionService, mAuthenticationMiddleware, httptest.NewRecorder()
			},
			wantErr: true,
			err:     errors.New("failed to read user from context"),
		},

		{
			title: "lack of bucketID",
			bodyRequestData: DTO.Delete{
				UserID: 1,
			},
			verifiedUser: true,
			withBucketID: false,
			setupMock: func(r *http.Request) (permissionHandler.PermissionService, commonInterfaces.AuthenticationMiddleware, http.ResponseWriter) {
				mPermissionService := new(permissionMocks.MockPermissionService)
				mAuthenticationMiddleware := new(authMocks.MockAuthenticationMiddleware)
				mAuthenticationMiddleware.On("VerifyToken", mock.Anything).Return(r, nil)
				return mPermissionService, mAuthenticationMiddleware, httptest.NewRecorder()
			},
			wantErr: true,
			err:     errors.New(`api error: lack of bucketID or provided bucketID is malformed`),
		},
		{
			title: "lack of permissionID",
			bodyRequestData: DTO.Delete{
				UserID: 1,
			},
			verifiedUser:     true,
			withBucketID:     true,
			withPermissionID: false,
			setupMock: func(r *http.Request) (permissionHandler.PermissionService, commonInterfaces.AuthenticationMiddleware, http.ResponseWriter) {
				mPermissionService := new(permissionMocks.MockPermissionService)
				mAuthenticationMiddleware := new(authMocks.MockAuthenticationMiddleware)
				mAuthenticationMiddleware.On("VerifyToken", mock.Anything).Return(r, nil)
				return mPermissionService, mAuthenticationMiddleware, httptest.NewRecorder()
			},
			wantErr: true,
			err:     errors.New(`api error: lack of permissionID or provided permissionID is malformed`),
		},

		{
			title: "failed to delete permission",
			bodyRequestData: DTO.Delete{
				UserID: 1,
			},
			verifiedUser:     true,
			withBucketID:     true,
			withPermissionID: true,
			setupMock: func(r *http.Request) (permissionHandler.PermissionService, commonInterfaces.AuthenticationMiddleware, http.ResponseWriter) {
				mPermissionService := new(permissionMocks.MockPermissionService)
				mPermissionService.On("Delete", mock.Anything, mock.Anything, mock.Anything, mock.Anything, mock.Anything).Return(errors.New("failed to delete permission"))
				mAuthenticationMiddleware := new(authMocks.MockAuthenticationMiddleware)
				mAuthenticationMiddleware.On("VerifyToken", mock.Anything).Return(r, nil)
				return mPermissionService, mAuthenticationMiddleware, httptest.NewRecorder()
			},
			wantErr: true,
			err:     errors.New(`failed to delete permission`),
		},
	}

	for _, testScenario := range testScenarios {
		t.Run(testScenario.title, func(t *testing.T) {
			bodyBytes, err := jsonutil.MarshalData(testScenario.bodyRequestData)
			if err != nil {
				panic(err)
			}

			bodyReader := bytes.NewReader(bodyBytes)

			r, err := http.NewRequest(http.MethodDelete, "/buckets/1/permissions/1", bodyReader)
			if err != nil {
				panic(err)
			}
			if testScenario.withBucketID {
				r.SetPathValue("bucketID", "1")
			}
			if testScenario.withPermissionID {
				r.SetPathValue("permissionID", "1")
			}
			if testScenario.verifiedUser {
				r = request.SetContext(r, "id", 1)
			}
			loggerService := setupPermissionsHandlerDependencies()
			permissionService, authorizationMiddleware, w := testScenario.setupMock(r)
			permissionHandler := permissionHandler.NewPermissionHandler(permissionService, authorizationMiddleware, loggerService)

			err = permissionHandler.Delete(w, r)

			if (err != nil) != testScenario.wantErr {
				t.Errorf("Delete() err = %v, wantErr = %v", err, testScenario.wantErr)
			}

			if err != nil && testScenario.err != nil {
				if err.Error() != testScenario.err.Error() {
					t.Errorf("Delete() error = %v, scenarioError = %v", err, testScenario.err)
				}
			}
		})
	}
}
