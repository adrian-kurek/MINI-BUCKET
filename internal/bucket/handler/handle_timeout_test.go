package handler

import (
	"context"
	"errors"
	"testing"

	commonInterfaces "github.com/slodkiadrianek/MINI-BUCKET/common/interfaces"
	authMocks "github.com/slodkiadrianek/MINI-BUCKET/test/mocks/auth"
	bucketMocks "github.com/slodkiadrianek/MINI-BUCKET/test/mocks/bucket"
)

func TestHandleTimeout(t *testing.T) {
	type args struct {
		title     string
		setupMock func() (bucketService, commonInterfaces.AuthenticationMiddleware)
		inputErr  error
		err       error
	}

	testScenarios := []args{
		{
			title: "context deadline exceeded",
			setupMock: func() (bucketService, commonInterfaces.AuthenticationMiddleware) {
				mBucketService := new(bucketMocks.MockBucketService)
				mAuthenticationMiddleware := new(authMocks.MockAuthenticationMiddleware)
				return mBucketService, mAuthenticationMiddleware
			},
			inputErr: context.DeadlineExceeded,
			err:      errors.New("api error: "),
		},
		{
			title: "operation err",
			setupMock: func() (bucketService, commonInterfaces.AuthenticationMiddleware) {
				mBucketService := new(bucketMocks.MockBucketService)
				mAuthenticationMiddleware := new(authMocks.MockAuthenticationMiddleware)
				return mBucketService, mAuthenticationMiddleware
			},
			inputErr: errors.New("failed to perform an action"),
			err:      errors.New("failed to perform an action"),
		},
	}

	for _, testScenario := range testScenarios {
		t.Run(testScenario.title, func(t *testing.T) {
			loggerService := setupBucketHandlerDependencies()
			bucketService, authorizationMiddleware := testScenario.setupMock()
			bucketHandler := NewBucketHandler(bucketService, authorizationMiddleware, loggerService)

			err := bucketHandler.handleTimeout(testScenario.inputErr, "/")

			if err != nil && testScenario.err != nil {
				if err.Error() != testScenario.err.Error() {
					t.Errorf("handleTimeout() error = %v, scenarioError = %v", err, testScenario.err)
				}
			}
		})
	}
}
