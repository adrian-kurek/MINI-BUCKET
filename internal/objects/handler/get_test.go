package handler_test

import (
	"errors"
	"net/http"
	"net/http/httptest"
	"os"
	"testing"

	commonInterfaces "github.com/slodkiadrianek/MINI-BUCKET/common/interfaces"
	"github.com/slodkiadrianek/MINI-BUCKET/common/request"
	objectHandler "github.com/slodkiadrianek/MINI-BUCKET/internal/objects/handler"
	"github.com/slodkiadrianek/MINI-BUCKET/internal/objects/model"
	authMocks "github.com/slodkiadrianek/MINI-BUCKET/test/mocks/auth"
	objectMocks "github.com/slodkiadrianek/MINI-BUCKET/test/mocks/objects"
	"github.com/stretchr/testify/mock"
)

func TestGet(t *testing.T) {
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
			title:              "with proper data and public access",
			verifiedUser:       true,
			withProperFileName: true,
			withBucketID:       true,
			setupMock: func(r *http.Request) (objectHandler.ObjectService, commonInterfaces.AuthenticationMiddleware, http.ResponseWriter) {
				mObjectService := new(objectMocks.MockObjectService)
				mObjectService.On("HasPublicAccess", mock.Anything, mock.Anything).
					Return(true, nil)
				mObjectService.On("Get", mock.Anything, mock.Anything, mock.Anything, mock.Anything).
					Return(model.GetMetadata{ContentType: "text", SizeBytes: 1, ETAG: "test"}, "./uploads/0/test.txt", nil)
				mAuthenticationMiddleware := new(authMocks.MockAuthenticationMiddleware)
				mAuthenticationMiddleware.On("VerifyToken", mock.Anything).Return(r, nil)
				return mObjectService, mAuthenticationMiddleware, httptest.NewRecorder()
			},
			wantErr: false,
			err:     nil,
		},
		{
			title:              "with proper data and without public access",
			verifiedUser:       true,
			withProperFileName: true,
			withBucketID:       true,
			setupMock: func(r *http.Request) (objectHandler.ObjectService, commonInterfaces.AuthenticationMiddleware, http.ResponseWriter) {
				mObjectService := new(objectMocks.MockObjectService)
				mObjectService.On("HasPublicAccess", mock.Anything, mock.Anything).
					Return(false, nil)
				mObjectService.On("CheckReadPermissions", mock.Anything, mock.Anything, mock.Anything).
					Return(nil)
				mObjectService.On("Get", mock.Anything, mock.Anything, mock.Anything, mock.Anything).
					Return(model.GetMetadata{ContentType: "text", SizeBytes: 1, ETAG: "test"}, "./uploads/0/test.txt", nil)
				mAuthenticationMiddleware := new(authMocks.MockAuthenticationMiddleware)
				mAuthenticationMiddleware.On("VerifyToken", mock.Anything).Return(r, nil)
				return mObjectService, mAuthenticationMiddleware, httptest.NewRecorder()
			},
			wantErr: false,
			err:     nil,
		},
		{
			title:              "with proper data, without public access and with versionID",
			verifiedUser:       true,
			withProperFileName: true,
			withVersionID:      true,
			withBucketID:       true,
			setupMock: func(r *http.Request) (objectHandler.ObjectService, commonInterfaces.AuthenticationMiddleware, http.ResponseWriter) {
				mObjectService := new(objectMocks.MockObjectService)
				mObjectService.On("HasPublicAccess", mock.Anything, mock.Anything).
					Return(false, nil)
				mObjectService.On("CheckReadPermissions", mock.Anything, mock.Anything, mock.Anything).
					Return(nil)
				mObjectService.On("Get", mock.Anything, mock.Anything, mock.Anything, mock.Anything).
					Return(model.GetMetadata{ContentType: "text", SizeBytes: 1, ETAG: "test"}, "./uploads/0/test.txt", nil)
				mAuthenticationMiddleware := new(authMocks.MockAuthenticationMiddleware)
				mAuthenticationMiddleware.On("VerifyToken", mock.Anything).Return(r, nil)
				return mObjectService, mAuthenticationMiddleware, httptest.NewRecorder()
			},
			wantErr: false,
			err:     nil,
		},
		{
			title:              "Get failed",
			verifiedUser:       true,
			withProperFileName: true,
			withBucketID:       true,
			setupMock: func(r *http.Request) (objectHandler.ObjectService, commonInterfaces.AuthenticationMiddleware, http.ResponseWriter) {
				mObjectService := new(objectMocks.MockObjectService)
				mObjectService.On("HasPublicAccess", mock.Anything, mock.Anything).
					Return(false, nil)
				mObjectService.On("CheckReadPermissions", mock.Anything, mock.Anything, mock.Anything).
					Return(nil)
				mObjectService.On("Get", mock.Anything, mock.Anything, mock.Anything, mock.Anything).
					Return(model.GetMetadata{}, "", errors.New("failed to get an object"))
				mAuthenticationMiddleware := new(authMocks.MockAuthenticationMiddleware)
				mAuthenticationMiddleware.On("VerifyToken", mock.Anything).Return(r, nil)
				return mObjectService, mAuthenticationMiddleware, httptest.NewRecorder()
			},
			wantErr: true,
			err:     errors.New("failed to get an object"),
		},
		{
			title:              "with invalid file name",
			verifiedUser:       true,
			withProperFileName: false,
			withBucketID:       true,
			setupMock: func(r *http.Request) (objectHandler.ObjectService, commonInterfaces.AuthenticationMiddleware, http.ResponseWriter) {
				mObjectService := new(objectMocks.MockObjectService)
				mObjectService.On("HasPublicAccess", mock.Anything, mock.Anything).
					Return(false, nil)
				mObjectService.On("CheckReadPermissions", mock.Anything, mock.Anything, mock.Anything).
					Return(nil)
				mObjectService.On("Get", mock.Anything, mock.Anything, mock.Anything, mock.Anything).
					Return(model.GetMetadata{ContentType: "text", SizeBytes: 1, ETAG: "test"}, "./uploads/0/test.txt", nil)
				mAuthenticationMiddleware := new(authMocks.MockAuthenticationMiddleware)
				mAuthenticationMiddleware.On("VerifyToken", mock.Anything).Return(r, nil)
				return mObjectService, mAuthenticationMiddleware, httptest.NewRecorder()
			},
			wantErr: true,
			err:     nil,
		},
		{
			title:              "CheckReadPermissions failed",
			verifiedUser:       true,
			withProperFileName: true,
			withBucketID:       true,
			setupMock: func(r *http.Request) (objectHandler.ObjectService, commonInterfaces.AuthenticationMiddleware, http.ResponseWriter) {
				mObjectService := new(objectMocks.MockObjectService)
				mObjectService.On("HasPublicAccess", mock.Anything, mock.Anything).
					Return(false, nil)
				mObjectService.On("CheckReadPermissions", mock.Anything, mock.Anything, mock.Anything).
					Return(errors.New("failed to check read permissions"))
				mObjectService.On("Get", mock.Anything, mock.Anything, mock.Anything, mock.Anything).
					Return(model.GetMetadata{ContentType: "text", SizeBytes: 1, ETAG: "test"}, "./uploads/0/test.txt", nil)
				mAuthenticationMiddleware := new(authMocks.MockAuthenticationMiddleware)
				mAuthenticationMiddleware.On("VerifyToken", mock.Anything).Return(r, nil)
				return mObjectService, mAuthenticationMiddleware, httptest.NewRecorder()
			},
			wantErr: true,
			err:     errors.New("failed to check read permissions"),
		},
		{
			title:        "failed to authorize the user",
			verifiedUser: true,
			withBucketID: true,
			setupMock: func(r *http.Request) (objectHandler.ObjectService, commonInterfaces.AuthenticationMiddleware, http.ResponseWriter) {
				mObjectService := new(objectMocks.MockObjectService)
				mObjectService.On("HasPublicAccess", mock.Anything, mock.Anything).
					Return(false, nil)
				mObjectService.On("CheckReadPermissions", mock.Anything, mock.Anything, mock.Anything).
					Return(nil)
				mObjectService.On("Get", mock.Anything, mock.Anything, mock.Anything, mock.Anything).
					Return(model.GetMetadata{ContentType: "text", SizeBytes: 1, ETAG: "test"}, "./uploads/0/test.txt", nil)
				mAuthenticationMiddleware := new(authMocks.MockAuthenticationMiddleware)
				mAuthenticationMiddleware.On("VerifyToken", mock.Anything).Return(r, errors.New("provided token is invalid"))
				return mObjectService, mAuthenticationMiddleware, httptest.NewRecorder()
			},
			wantErr: true,
			err:     errors.New("provided token is invalid"),
		},
		{
			title:        "failed to read user from token",
			withBucketID: true,
			setupMock: func(r *http.Request) (objectHandler.ObjectService, commonInterfaces.AuthenticationMiddleware, http.ResponseWriter) {
				mObjectService := new(objectMocks.MockObjectService)
				mObjectService.On("HasPublicAccess", mock.Anything, mock.Anything).
					Return(false, nil)
				mObjectService.On("CheckReadPermissions", mock.Anything, mock.Anything, mock.Anything).
					Return(nil)
				mObjectService.On("Get", mock.Anything, mock.Anything, mock.Anything, mock.Anything).
					Return(model.GetMetadata{ContentType: "text", SizeBytes: 1, ETAG: "test"}, "./uploads/0/test.txt", nil)
				mAuthenticationMiddleware := new(authMocks.MockAuthenticationMiddleware)
				mAuthenticationMiddleware.On("VerifyToken", mock.Anything).Return(r, nil)
				return mObjectService, mAuthenticationMiddleware, httptest.NewRecorder()
			},
			wantErr: true,
			err:     nil,
		},
		{
			title:        "hasPublicAccess failed",
			withBucketID: true,
			setupMock: func(r *http.Request) (objectHandler.ObjectService, commonInterfaces.AuthenticationMiddleware, http.ResponseWriter) {
				mObjectService := new(objectMocks.MockObjectService)
				mObjectService.On("HasPublicAccess", mock.Anything, mock.Anything).
					Return(false, errors.New("failed to get info about public"))
				mAuthenticationMiddleware := new(authMocks.MockAuthenticationMiddleware)
				return mObjectService, mAuthenticationMiddleware, httptest.NewRecorder()
			},
			wantErr: true,
			err:     errors.New("failed to get info about public"),
		},
		{
			title:        "lack of bucketID ",
			withBucketID: false,
			setupMock: func(r *http.Request) (objectHandler.ObjectService, commonInterfaces.AuthenticationMiddleware, http.ResponseWriter) {
				mObjectService := new(objectMocks.MockObjectService)
				mAuthenticationMiddleware := new(authMocks.MockAuthenticationMiddleware)
				return mObjectService, mAuthenticationMiddleware, httptest.NewRecorder()
			},
			wantErr: true,
			err:     errors.New("api error: lack of bucketID or provided bucketID is malformed"),
		},
	}

	for _, testScenario := range testScenarios {
		t.Run(testScenario.title, func(t *testing.T) {
			r, err := http.NewRequest(http.MethodGet, "/buckets/0/objects/test.txt", nil)
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

			if !testScenario.wantErr {
				if err := os.MkdirAll("./uploads/0", 0o755); err != nil {
					panic(err)
				}
				f, err := os.Create("./uploads/0/test.txt")
				if err != nil {
					panic(err)
				}
				defer f.Close()
			}

			loggerService := setupObjectHandlerDependencies()
			objectService, authorizationMiddleware, w := testScenario.setupMock(r)
			h := objectHandler.New(loggerService, authorizationMiddleware, objectService)

			err = h.Get(w, r)

			if !testScenario.wantErr {
				err = os.RemoveAll("./uploads/0/objects/test.txt")
				if err != nil {
					panic(err)
				}
			}

			if (err != nil) != testScenario.wantErr {
				t.Errorf("Get() err = %v, wantErr = %v", err, testScenario.wantErr)
			}

			if err != nil && testScenario.err != nil {
				if err.Error() != testScenario.err.Error() {
					t.Errorf("Get() error = %v, scenarioError = %v", err, testScenario.err)
				}
			}
		})
	}
}

func TestGetMetadata(t *testing.T) {
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
			title:              "with proper data and public access",
			verifiedUser:       true,
			withProperFileName: true,
			withBucketID:       true,
			setupMock: func(r *http.Request) (objectHandler.ObjectService, commonInterfaces.AuthenticationMiddleware, http.ResponseWriter) {
				mObjectService := new(objectMocks.MockObjectService)
				mObjectService.On("HasPublicAccess", mock.Anything, mock.Anything).
					Return(true, nil)
				mObjectService.On("GetMetadata", mock.Anything, mock.Anything, mock.Anything, mock.Anything).
					Return(model.GetMetadata{ContentType: "text", SizeBytes: 1, ETAG: "test"}, nil)
				mAuthenticationMiddleware := new(authMocks.MockAuthenticationMiddleware)
				mAuthenticationMiddleware.On("VerifyToken", mock.Anything).Return(r, nil)
				return mObjectService, mAuthenticationMiddleware, httptest.NewRecorder()
			},
			wantErr: false,
			err:     nil,
		},
		{
			title:              "GetMetadata failed",
			verifiedUser:       true,
			withProperFileName: true,
			withBucketID:       true,
			setupMock: func(r *http.Request) (objectHandler.ObjectService, commonInterfaces.AuthenticationMiddleware, http.ResponseWriter) {
				mObjectService := new(objectMocks.MockObjectService)
				mObjectService.On("HasPublicAccess", mock.Anything, mock.Anything).
					Return(true, nil)
				mObjectService.On("GetMetadata", mock.Anything, mock.Anything, mock.Anything, mock.Anything).
					Return(model.GetMetadata{}, errors.New("failed to get metadata"))
				mAuthenticationMiddleware := new(authMocks.MockAuthenticationMiddleware)
				mAuthenticationMiddleware.On("VerifyToken", mock.Anything).Return(r, nil)
				return mObjectService, mAuthenticationMiddleware, httptest.NewRecorder()
			},
			wantErr: true,
			err:     errors.New("failed to get metadata"),
		},
		{
			title:              "with proper data without  public access",
			verifiedUser:       true,
			withProperFileName: true,
			withBucketID:       true,
			setupMock: func(r *http.Request) (objectHandler.ObjectService, commonInterfaces.AuthenticationMiddleware, http.ResponseWriter) {
				mObjectService := new(objectMocks.MockObjectService)
				mObjectService.On("HasPublicAccess", mock.Anything, mock.Anything).
					Return(false, nil)

				mObjectService.On("CheckReadPermissions", mock.Anything, mock.Anything, mock.Anything).
					Return(nil)
				mObjectService.On("GetMetadata", mock.Anything, mock.Anything, mock.Anything, mock.Anything).
					Return(model.GetMetadata{ContentType: "text", SizeBytes: 1, ETAG: "test"}, nil)
				mAuthenticationMiddleware := new(authMocks.MockAuthenticationMiddleware)
				mAuthenticationMiddleware.On("VerifyToken", mock.Anything).Return(r, nil)
				return mObjectService, mAuthenticationMiddleware, httptest.NewRecorder()
			},
			wantErr: false,
			err:     nil,
		},
		{
			title:              "CheckReadPermissions failed",
			verifiedUser:       true,
			withProperFileName: true,
			withBucketID:       true,
			setupMock: func(r *http.Request) (objectHandler.ObjectService, commonInterfaces.AuthenticationMiddleware, http.ResponseWriter) {
				mObjectService := new(objectMocks.MockObjectService)
				mObjectService.On("HasPublicAccess", mock.Anything, mock.Anything).
					Return(false, nil)

				mObjectService.On("CheckReadPermissions", mock.Anything, mock.Anything, mock.Anything).
					Return(errors.New("failed to check read permissions"))
				mAuthenticationMiddleware := new(authMocks.MockAuthenticationMiddleware)
				mAuthenticationMiddleware.On("VerifyToken", mock.Anything).Return(r, nil)
				return mObjectService, mAuthenticationMiddleware, httptest.NewRecorder()
			},
			wantErr: true,
			err:     errors.New("failed to check read permissions"),
		},
		{
			title:        "failed to read user token",
			verifiedUser: false,
			withBucketID: true,
			setupMock: func(r *http.Request) (objectHandler.ObjectService, commonInterfaces.AuthenticationMiddleware, http.ResponseWriter) {
				mObjectService := new(objectMocks.MockObjectService)
				mObjectService.On("HasPublicAccess", mock.Anything, mock.Anything).
					Return(false, nil)

				mObjectService.On("CheckReadPermissions", mock.Anything, mock.Anything, mock.Anything).
					Return(nil)
				mAuthenticationMiddleware := new(authMocks.MockAuthenticationMiddleware)
				mAuthenticationMiddleware.On("VerifyToken", mock.Anything).Return(r, nil)
				return mObjectService, mAuthenticationMiddleware, httptest.NewRecorder()
			},
			wantErr: true,
			err:     nil,
		},
		{
			title:              "VerifyToken failed",
			verifiedUser:       true,
			withProperFileName: true,
			withBucketID:       true,
			setupMock: func(r *http.Request) (objectHandler.ObjectService, commonInterfaces.AuthenticationMiddleware, http.ResponseWriter) {
				mObjectService := new(objectMocks.MockObjectService)
				mObjectService.On("HasPublicAccess", mock.Anything, mock.Anything).
					Return(false, nil)

				mObjectService.On("CheckReadPermissions", mock.Anything, mock.Anything, mock.Anything).
					Return(nil)
				mObjectService.On("GetMetadata", mock.Anything, mock.Anything, mock.Anything, mock.Anything).
					Return(model.GetMetadata{ContentType: "text", SizeBytes: 1, ETAG: "test"}, nil)
				mAuthenticationMiddleware := new(authMocks.MockAuthenticationMiddleware)
				mAuthenticationMiddleware.On("VerifyToken", mock.Anything).Return(r, errors.New("failed to verify token"))
				return mObjectService, mAuthenticationMiddleware, httptest.NewRecorder()
			},
			wantErr: true,
			err:     errors.New("failed to verify token"),
		},
		{
			title:        "HasPublicAccess failed",
			withBucketID: true,
			setupMock: func(r *http.Request) (objectHandler.ObjectService, commonInterfaces.AuthenticationMiddleware, http.ResponseWriter) {
				mObjectService := new(objectMocks.MockObjectService)
				mObjectService.On("HasPublicAccess", mock.Anything, mock.Anything).
					Return(false, errors.New("failed to get info about public access"))
				mAuthenticationMiddleware := new(authMocks.MockAuthenticationMiddleware)
				return mObjectService, mAuthenticationMiddleware, httptest.NewRecorder()
			},
			wantErr: true,
			err:     errors.New("failed to get info about public access"),
		},
		{
			title:        "lack of bucketID",
			withBucketID: false,
			setupMock: func(r *http.Request) (objectHandler.ObjectService, commonInterfaces.AuthenticationMiddleware, http.ResponseWriter) {
				mObjectService := new(objectMocks.MockObjectService)
				mAuthenticationMiddleware := new(authMocks.MockAuthenticationMiddleware)
				return mObjectService, mAuthenticationMiddleware, httptest.NewRecorder()
			},
			wantErr: true,
			err:     errors.New("api error: lack of bucketID or provided bucketID is malformed"),
		},
	}

	for _, testScenario := range testScenarios {
		t.Run(testScenario.title, func(t *testing.T) {
			r, err := http.NewRequest(http.MethodGet, "/buckets/0/objects/test.txt", nil)
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

			err = h.GetMetadata(w, r)

			if (err != nil) != testScenario.wantErr {
				t.Errorf("GetMetadata() err = %v, wantErr = %v", err, testScenario.wantErr)
			}

			if err != nil && testScenario.err != nil {
				if err.Error() != testScenario.err.Error() {
					t.Errorf("GetMetadata() error = %v, scenarioError = %v", err, testScenario.err)
				}
			}
		})
	}
}
