package handler

import (
	"context"
	"errors"
	"testing"

	commonInterfaces "github.com/slodkiadrianek/MINI-BUCKET/common/interfaces"
	authMocks "github.com/slodkiadrianek/MINI-BUCKET/test/mocks/auth"
	permissionMocks "github.com/slodkiadrianek/MINI-BUCKET/test/mocks/permissions"
)

func TestHandleTimeout(t *testing.T) {
	type args struct {
		title     string
		setupMock func() (permissionService, commonInterfaces.AuthenticationMiddleware)
		inputErr  error
		err       error
	}

	testScenarios := []args{
		{
			title: "context deadline exceeded",
			setupMock: func() (permissionService, commonInterfaces.AuthenticationMiddleware) {
				mPermissionService := new(permissionMocks.MockPermissionService)
				mAuthenticationMiddleware := new(authMocks.MockAuthenticationMiddleware)
				return mPermissionService, mAuthenticationMiddleware
			},
			inputErr: context.DeadlineExceeded,
			err:      errors.New("api error: "),
		},
		{
			title: "operation err",
			setupMock: func() (permissionService, commonInterfaces.AuthenticationMiddleware) {
				mPermissionService := new(permissionMocks.MockPermissionService)
				mAuthenticationMiddleware := new(authMocks.MockAuthenticationMiddleware)
				return mPermissionService, mAuthenticationMiddleware
			},
			inputErr: errors.New("failed to perform an action"),
			err:      errors.New("failed to perform an action"),
		},
	}

	for _, testScenario := range testScenarios {
		t.Run(testScenario.title, func(t *testing.T) {
			loggerService := setupPermissionsHandlerDependencies()
			permissionService, authorizationMiddleware := testScenario.setupMock()
			permissionHandler := NewPermissionHandler(permissionService, authorizationMiddleware, loggerService)

			err := permissionHandler.handleTimeout(testScenario.inputErr, "/")

			if err != nil && testScenario.err != nil {
				if err.Error() != testScenario.err.Error() {
					t.Errorf("handleTimeout() error = %v, scenarioError = %v", err, testScenario.err)
				}
			}
		})
	}
}
