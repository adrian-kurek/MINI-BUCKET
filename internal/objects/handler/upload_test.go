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
	objectHandler "github.com/slodkiadrianek/MINI-BUCKET/internal/objects/handler"
	DTO "github.com/slodkiadrianek/MINI-BUCKET/internal/permissions/DTO"
	authMocks "github.com/slodkiadrianek/MINI-BUCKET/test/mocks/auth"
	objectMocks "github.com/slodkiadrianek/MINI-BUCKET/test/mocks/objects"
	"github.com/stretchr/testify/mock"
)

func TestUpload(t *testing.T) {
	type args struct {
		title              string
		bodyRequestData    DTO.Upsert
		verifiedUser       bool
		withProperFileName bool
		withBucketID       bool
		setupMock          func(r *http.Request) (objectHandler.ObjectService, commonInterfaces.AuthenticationMiddleware, http.ResponseWriter)
		wantErr            bool
		err                error
	}

	testScenarios := []args{
		{
			title: "with proper data without objectID",
			bodyRequestData: DTO.Upsert{
				UserID:     1,
				Permission: 7,
			},
			verifiedUser:       true,
			withBucketID:       true,
			withProperFileName: true,
			setupMock: func(r *http.Request) (objectHandler.ObjectService, commonInterfaces.AuthenticationMiddleware, http.ResponseWriter) {
				mObjectService := new(objectMocks.MockObjectService)
				mObjectService.On("Upload", mock.Anything, mock.Anything, mock.Anything, mock.Anything, mock.Anything).
					Return(nil)
				mAuthenticationMiddleware := new(authMocks.MockAuthenticationMiddleware)
				mAuthenticationMiddleware.On("VerifyToken", mock.Anything).Return(r, nil)
				return mObjectService, mAuthenticationMiddleware, httptest.NewRecorder()
			},
			wantErr: false,
			err:     nil,
		},
		{
			title: "invalid file name",
			bodyRequestData: DTO.Upsert{
				UserID:     1,
				Permission: 7,
			},
			verifiedUser:       true,
			withBucketID:       true,
			withProperFileName: false,
			setupMock: func(r *http.Request) (objectHandler.ObjectService, commonInterfaces.AuthenticationMiddleware, http.ResponseWriter) {
				mObjectService := new(objectMocks.MockObjectService)
				mObjectService.On("Upload",
					mock.Anything,
					mock.Anything,
					mock.Anything,
					mock.Anything,
					mock.Anything,
				).Return(nil)
				mAuthenticationMiddleware := new(authMocks.MockAuthenticationMiddleware)
				mAuthenticationMiddleware.On("VerifyToken", mock.Anything).Return(r, nil)
				return mObjectService, mAuthenticationMiddleware, httptest.NewRecorder()
			},
			wantErr: true,
			err:     errors.New("api error: invalid file name"),
		},
		{
			title: "with proper data with objectID",
			bodyRequestData: DTO.Upsert{
				UserID:     1,
				Permission: 7,
			},
			verifiedUser:       true,
			withBucketID:       true,
			withProperFileName: true,
			setupMock: func(r *http.Request) (objectHandler.ObjectService, commonInterfaces.AuthenticationMiddleware, http.ResponseWriter) {
				mObjectService := new(objectMocks.MockObjectService)
				mObjectService.On("Upload", mock.Anything, mock.Anything, mock.Anything, mock.Anything, mock.Anything).
					Return(nil)
				mAuthenticationMiddleware := new(authMocks.MockAuthenticationMiddleware)
				mAuthenticationMiddleware.On("VerifyToken", mock.Anything).Return(r, nil)
				return mObjectService, mAuthenticationMiddleware, httptest.NewRecorder()
			},
			wantErr: false,
			err:     nil,
		},
		{
			title: "failed to authorize user",
			bodyRequestData: DTO.Upsert{
				UserID:     1,
				Permission: 7,
			},
			verifiedUser:       true,
			withBucketID:       true,
			withProperFileName: true,
			setupMock: func(r *http.Request) (objectHandler.ObjectService, commonInterfaces.AuthenticationMiddleware, http.ResponseWriter) {
				mObjectService := new(objectMocks.MockObjectService)
				mObjectService.On("Upload", mock.Anything, mock.Anything, mock.Anything, mock.Anything, mock.Anything).
					Return(nil)
				mAuthenticationMiddleware := new(authMocks.MockAuthenticationMiddleware)
				mAuthenticationMiddleware.On("VerifyToken", mock.Anything).
					Return(r, errors.New("failed to auhthorize the user"))
				return mObjectService, mAuthenticationMiddleware, httptest.NewRecorder()
			},
			wantErr: true,
			err:     errors.New("failed to auhthorize the user"),
		},

		{
			title: "lack of userID",
			bodyRequestData: DTO.Upsert{
				Permission: 7,
			},
			verifiedUser:       false,
			withBucketID:       false,
			withProperFileName: true,
			setupMock: func(r *http.Request) (objectHandler.ObjectService, commonInterfaces.AuthenticationMiddleware, http.ResponseWriter) {
				mObjectService := new(objectMocks.MockObjectService)
				mAuthenticationMiddleware := new(authMocks.MockAuthenticationMiddleware)
				mAuthenticationMiddleware.On("VerifyToken", mock.Anything).Return(r, nil)
				return mObjectService, mAuthenticationMiddleware, httptest.NewRecorder()
			},
			wantErr: true,
			err:     errors.New("failed to read user from context"),
		},

		{
			title: "failed to read user id from context",
			bodyRequestData: DTO.Upsert{
				UserID:     1,
				Permission: 7,
			},
			verifiedUser:       false,
			withBucketID:       false,
			withProperFileName: true,
			setupMock: func(r *http.Request) (objectHandler.ObjectService, commonInterfaces.AuthenticationMiddleware, http.ResponseWriter) {
				mObjectService := new(objectMocks.MockObjectService)
				mAuthenticationMiddleware := new(authMocks.MockAuthenticationMiddleware)
				mAuthenticationMiddleware.On("VerifyToken", mock.Anything).Return(r, nil)
				return mObjectService, mAuthenticationMiddleware, httptest.NewRecorder()
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
			verifiedUser:       true,
			withBucketID:       false,
			withProperFileName: true,
			setupMock: func(r *http.Request) (objectHandler.ObjectService, commonInterfaces.AuthenticationMiddleware, http.ResponseWriter) {
				mObjectService := new(objectMocks.MockObjectService)
				mAuthenticationMiddleware := new(authMocks.MockAuthenticationMiddleware)
				mAuthenticationMiddleware.On("VerifyToken", mock.Anything).Return(r, nil)
				return mObjectService, mAuthenticationMiddleware, httptest.NewRecorder()
			},
			wantErr: true,
			err:     errors.New(`api error: lack of bucketID or provided bucketID is malformed`),
		},

		{
			title: "failed to create permission",
			bodyRequestData: DTO.Upsert{
				UserID:     1,
				Permission: 7,
			},
			verifiedUser:       true,
			withBucketID:       true,
			withProperFileName: true,
			setupMock: func(r *http.Request) (objectHandler.ObjectService, commonInterfaces.AuthenticationMiddleware, http.ResponseWriter) {
				mObjectService := new(objectMocks.MockObjectService)
				mObjectService.On("Upload", mock.Anything, mock.Anything, mock.Anything, mock.Anything, mock.Anything).
					Return(errors.New("failed to create new permission"))
				mAuthenticationMiddleware := new(authMocks.MockAuthenticationMiddleware)
				mAuthenticationMiddleware.On("VerifyToken", mock.Anything).Return(r, nil)
				return mObjectService, mAuthenticationMiddleware, httptest.NewRecorder()
			},
			wantErr: true,
			err:     errors.New(`failed to create new permission`),
		},
	}

	for _, testScenario := range testScenarios {
		t.Run(testScenario.title, func(t *testing.T) {
			bodyBytes, err := jsonutil.MarshalData(testScenario.bodyRequestData)
			if err != nil {
				panic(err)
			}

			bodyReader := bytes.NewReader(bodyBytes)
			r, err := http.NewRequest(http.MethodPut, "/buckets/1/permissions", bodyReader)
			if err != nil {
				panic(err)
			}

			if testScenario.withBucketID {
				r.SetPathValue("bucketID", "1")
			}

			if testScenario.verifiedUser {
				r = request.SetContext(r, "id", 1)
			}

			if testScenario.withProperFileName {
				r.Header.Set("X-Filename", "input.txt")
			}

			loggerService := setupObjectHandlerDependencies()
			objectService, authorizationMiddleware, w := testScenario.setupMock(r)
			h := objectHandler.New(loggerService, authorizationMiddleware, objectService)

			err = h.Upload(w, r)

			if (err != nil) != testScenario.wantErr {
				t.Errorf("Upload() err = %v, wantErr = %v", err, testScenario.wantErr)
			}

			if err != nil && testScenario.err != nil {
				if err.Error() != testScenario.err.Error() {
					t.Errorf("Upload() error = %v, scenarioError = %v", err, testScenario.err)
				}
			}
		})
	}
}
