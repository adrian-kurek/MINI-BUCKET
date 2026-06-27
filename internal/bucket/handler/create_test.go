package handler

import (
	"bytes"
	"errors"
	"net/http"
	"net/http/httptest"
	"testing"

	commonInterfaces "github.com/slodkiadrianek/MINI-BUCKET/common/interfaces"
	jsonutil "github.com/slodkiadrianek/MINI-BUCKET/common/json_util"
	"github.com/slodkiadrianek/MINI-BUCKET/common/request"
	DTO "github.com/slodkiadrianek/MINI-BUCKET/internal/bucket/DTO"
	authMocks "github.com/slodkiadrianek/MINI-BUCKET/test/mocks/auth"
	bucketMocks "github.com/slodkiadrianek/MINI-BUCKET/test/mocks/bucket"
	"github.com/stretchr/testify/mock"
)

func TestCreate(t *testing.T) {
	type args struct {
		title           string
		bodyRequestData DTO.BucketInput
		verifiedUser    bool
		setupMock       func(r *http.Request) (bucketService, commonInterfaces.AuthenticationMiddleware, http.ResponseWriter)
		wantErr         bool
		err             error
	}

	testScenarios := []args{
		{
			title: "with proper data",
			bodyRequestData: DTO.BucketInput{
				Name:              "test",
				VersioningEnabled: true,
				EncryptionEnabled: true,
				PublicAccess:      true,
				StorageClass:      "STANDARD",
			},
			verifiedUser: true,
			setupMock: func(r *http.Request) (bucketService, commonInterfaces.AuthenticationMiddleware, http.ResponseWriter) {
				mBucketService := new(bucketMocks.MockBucketService)
				mBucketService.On("Create", mock.Anything, mock.Anything, mock.Anything).Return(nil)
				mAuthenticationMiddleware := new(authMocks.MockAuthenticationMiddleware)
				mAuthenticationMiddleware.On("VerifyToken", mock.Anything).Return(r, nil)
				return mBucketService, mAuthenticationMiddleware, httptest.NewRecorder()
			},
			wantErr: false,
			err:     nil,
		},
		{
			title: "failed to validate request data",
			bodyRequestData: DTO.BucketInput{
				Name:              "te",
				VersioningEnabled: true,
				EncryptionEnabled: true,
				PublicAccess:      true,
				StorageClass:      "STANDARD",
			},
			verifiedUser: true,
			setupMock: func(r *http.Request) (bucketService, commonInterfaces.AuthenticationMiddleware, http.ResponseWriter) {
				mBucketService := new(bucketMocks.MockBucketService)
				mAuthenticationMiddleware := new(authMocks.MockAuthenticationMiddleware)
				mAuthenticationMiddleware.On("VerifyToken", mock.Anything).Return(r, nil)
				return mBucketService, mAuthenticationMiddleware, httptest.NewRecorder()
			},
			wantErr: true,
			err:     errors.New("api error: the Name field must be at least 3 characters long"),
		},

		{
			title: "failed to read userID from token",
			bodyRequestData: DTO.BucketInput{
				Name:              "test",
				VersioningEnabled: true,
				EncryptionEnabled: true,
				PublicAccess:      true,
				StorageClass:      "STANDARD",
			},
			verifiedUser: false,
			setupMock: func(r *http.Request) (bucketService, commonInterfaces.AuthenticationMiddleware, http.ResponseWriter) {
				mBucketService := new(bucketMocks.MockBucketService)
				mAuthenticationMiddleware := new(authMocks.MockAuthenticationMiddleware)
				mAuthenticationMiddleware.On("VerifyToken", mock.Anything).Return(r, nil)
				return mBucketService, mAuthenticationMiddleware, httptest.NewRecorder()
			},
			wantErr: true,
			err:     errors.New("failed to read user from context"),
		},

		{
			title: "failed to create new bucket",
			bodyRequestData: DTO.BucketInput{
				Name:              "test",
				VersioningEnabled: true,
				EncryptionEnabled: true,
				PublicAccess:      true,
				StorageClass:      "STANDARD",
			},
			verifiedUser: true,
			setupMock: func(r *http.Request) (bucketService, commonInterfaces.AuthenticationMiddleware, http.ResponseWriter) {
				mBucketService := new(bucketMocks.MockBucketService)
				mBucketService.On("Create", mock.Anything, mock.Anything, mock.Anything).Return(errors.New("failed to create the new bucket"))
				mAuthenticationMiddleware := new(authMocks.MockAuthenticationMiddleware)
				mAuthenticationMiddleware.On("VerifyToken", mock.Anything).Return(r, nil)
				return mBucketService, mAuthenticationMiddleware, httptest.NewRecorder()
			},
			wantErr: true,
			err:     errors.New("failed to create the new bucket"),
		},
	}

	for _, testScenario := range testScenarios {
		t.Run(testScenario.title, func(t *testing.T) {
			bodyBytes, err := jsonutil.MarshalData(testScenario.bodyRequestData)
			if err != nil {
				panic(err)
			}

			bodyReader := bytes.NewReader(bodyBytes)
			r, err := http.NewRequest(http.MethodPost, "/buckets", bodyReader)
			if err != nil {
				panic(err)
			}
			if testScenario.verifiedUser {
				r = request.SetContext(r, "id", 1)
			}

			loggerService := setupBucketHandlerDependencies()
			bucketService, authorizationMiddleware, w := testScenario.setupMock(r)
			permissionHandler := NewBucketHandler(bucketService, authorizationMiddleware, loggerService)

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
