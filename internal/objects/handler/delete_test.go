package handler_test

import (
	"errors"
	"net/http"
	"net/http/httptest"
	"testing"

	commonInterfaces "github.com/slodkiadrianek/MINI-BUCKET/common/interfaces"
	"github.com/slodkiadrianek/MINI-BUCKET/common/request"
	objectHandler "github.com/slodkiadrianek/MINI-BUCKET/internal/objects/handler"
	authMocks "github.com/slodkiadrianek/MINI-BUCKET/test/mocks/auth"
	objectMocks "github.com/slodkiadrianek/MINI-BUCKET/test/mocks/objects"
	"github.com/stretchr/testify/mock"
)

func TestDelete(t *testing.T) {
	type args struct {
		title              string
		verifiedUser       bool
		withProperFileName bool
		withVersionID      bool
		withBucketID       bool
		setupMock          func(r *http.Request) (objectHandler.ObjectService, commonInterfaces.AuthenticationMiddleware, http.ResponseWriter)
		wantErr            bool
		err                error
	}

	testScenarios := []args{
		{
			title:              "with proper data ",
			verifiedUser:       true,
			withProperFileName: true,
			withBucketID:       true,
			setupMock: func(r *http.Request) (objectHandler.ObjectService, commonInterfaces.AuthenticationMiddleware, http.ResponseWriter) {
				mObjectService := new(objectMocks.MockObjectService)
				mObjectService.On("Delete", mock.Anything, mock.Anything, mock.Anything, mock.Anything, mock.Anything).
					Return(nil)
				mAuthenticationMiddleware := new(authMocks.MockAuthenticationMiddleware)
				mAuthenticationMiddleware.On("VerifyToken", mock.Anything).Return(r, nil)
				return mObjectService, mAuthenticationMiddleware, httptest.NewRecorder()
			},
			wantErr: false,
			err:     nil,
		},
		{
			title:              "Delete failed",
			verifiedUser:       true,
			withProperFileName: true,
			withBucketID:       true,
			setupMock: func(r *http.Request) (objectHandler.ObjectService, commonInterfaces.AuthenticationMiddleware, http.ResponseWriter) {
				mObjectService := new(objectMocks.MockObjectService)
				mObjectService.On("Delete", mock.Anything, mock.Anything, mock.Anything, mock.Anything, mock.Anything).
					Return(errors.New("failed to delete object"))
				mAuthenticationMiddleware := new(authMocks.MockAuthenticationMiddleware)
				mAuthenticationMiddleware.On("VerifyToken", mock.Anything).Return(r, nil)
				return mObjectService, mAuthenticationMiddleware, httptest.NewRecorder()
			},
			wantErr: true,
			err:     errors.New("failed to delete object"),
		},
		{
			title:              "failed to verify file name",
			verifiedUser:       true,
			withVersionID:      true,
			withBucketID:       true,
			setupMock: func(r *http.Request) (objectHandler.ObjectService, commonInterfaces.AuthenticationMiddleware, http.ResponseWriter) {
				mObjectService := new(objectMocks.MockObjectService)
				mObjectService.On("Delete", mock.Anything, mock.Anything, mock.Anything, mock.Anything, mock.Anything).
					Return(nil)
				mAuthenticationMiddleware := new(authMocks.MockAuthenticationMiddleware)
				mAuthenticationMiddleware.On("VerifyToken", mock.Anything).Return(r, nil)
				return mObjectService, mAuthenticationMiddleware, httptest.NewRecorder()
			},
			wantErr: true,
			err:     errors.New("api error: invalid file name"),
		},
		{
			title:              "without bucket id",
			verifiedUser:       true,
			withProperFileName: true,
			setupMock: func(r *http.Request) (objectHandler.ObjectService, commonInterfaces.AuthenticationMiddleware, http.ResponseWriter) {
				mObjectService := new(objectMocks.MockObjectService)
				mAuthenticationMiddleware := new(authMocks.MockAuthenticationMiddleware)
				mAuthenticationMiddleware.On("VerifyToken", mock.Anything).Return(r, nil)
				return mObjectService, mAuthenticationMiddleware, httptest.NewRecorder()
			},
			wantErr: true,
			err:     errors.New("api error: lack of bucketID or provided bucketID is malformed"),
		},
		{
			title:              "failed to verify user",
			verifiedUser:       true,
			withProperFileName: true,
			withBucketID:       true,
			setupMock: func(r *http.Request) (objectHandler.ObjectService, commonInterfaces.AuthenticationMiddleware, http.ResponseWriter) {
				mObjectService := new(objectMocks.MockObjectService)
				mAuthenticationMiddleware := new(authMocks.MockAuthenticationMiddleware)
				mAuthenticationMiddleware.On("VerifyToken", mock.Anything).Return(r, errors.New("failed to verify token of the user"))
				return mObjectService, mAuthenticationMiddleware, httptest.NewRecorder()
			},
			wantErr: true,
			err:     errors.New("failed to verify token of the user"),
		},
	}

	for _, testScenario := range testScenarios {
		t.Run(testScenario.title, func(t *testing.T) {
			r, err := http.NewRequest(http.MethodDelete, "/buckets/0/objects/test.txt", nil)
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
				r.SetPathValue("objectKey", "test.txt")
			}

			if testScenario.withVersionID {
				q := r.URL.Query()
				q.Set("versionID", "1")
				r.URL.RawQuery = q.Encode()
			}

			loggerService := setupObjectHandlerDependencies()
			objectService, authorizationMiddleware, w := testScenario.setupMock(r)
			h := objectHandler.New(loggerService, authorizationMiddleware, objectService)

			err = h.Delete(w, r)

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
