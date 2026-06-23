package handler

import (
	"context"
	"errors"
	"testing"

	commonInterfaces "github.com/slodkiadrianek/MINI-BUCKET/common/interfaces"
	authMocks "github.com/slodkiadrianek/MINI-BUCKET/test/mocks/auth"
	objectMocks "github.com/slodkiadrianek/MINI-BUCKET/test/mocks/objects"
)

func TestHandleTimeout(t *testing.T) {
	type args struct {
		title     string
		setupMock func() (objectService, commonInterfaces.AuthenticationMiddleware)
		inputErr  error
		err       error
	}

	testScenarios := []args{
		{
			title: "context deadline exceeded",
			setupMock: func() (objectService, commonInterfaces.AuthenticationMiddleware) {
				mObjectService := new(objectMocks.MockObjectService)
				mAuthenticationMiddleware := new(authMocks.MockAuthenticationMiddleware)
				return mObjectService, mAuthenticationMiddleware
			},
			inputErr: context.DeadlineExceeded,
			err:      errors.New("api error: "),
		},
		{
			title: "operation err",
			setupMock: func() (objectService, commonInterfaces.AuthenticationMiddleware) {
				mObjectService := new(objectMocks.MockObjectService)
				mAuthenticationMiddleware := new(authMocks.MockAuthenticationMiddleware)
				return mObjectService, mAuthenticationMiddleware
			},
			inputErr: errors.New("failed to perform an action"),
			err:      errors.New("failed to perform an action"),
		},
	}

	for _, testScenario := range testScenarios {
		t.Run(testScenario.title, func(t *testing.T) {
			loggerService := setupObjectHandlerDependencies()
			objectService, authorizationMiddleware := testScenario.setupMock()
			objectHandler := NewObjectHandler(loggerService, authorizationMiddleware, objectService)

			err := objectHandler.handleTimeout(testScenario.inputErr, "/")

			if err != nil && testScenario.err != nil {
				if err.Error() != testScenario.err.Error() {
					t.Errorf("handleTimeout() error = %v, scenarioError = %v", err, testScenario.err)
				}
			}
		})
	}
}
