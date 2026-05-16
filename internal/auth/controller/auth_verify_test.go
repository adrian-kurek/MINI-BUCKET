package controller

import (
	"context"
	"errors"
	"net/http"
	"net/http/httptest"
	"testing"

	commonInterfaces "github.com/slodkiadrianek/MINI-BUCKET/internal/common/interfaces"
	authMocks "github.com/slodkiadrianek/MINI-BUCKET/test/mocks/auth"
	"github.com/stretchr/testify/mock"
)



func TestVerify(t *testing.T) {
	type args struct {
		title      string
		setupMocks func() (commonInterfaces.AuthorizationMiddleware, authService, http.ResponseWriter)
		wantErr    bool
		err        error
	}

	testsScenarios := []args{
		{
			title: "with proper data",
			setupMocks: func() (commonInterfaces.AuthorizationMiddleware, authService, http.ResponseWriter) {
				mAuthorizationMiddleware := new(authMocks.MockAuthorizationMiddleware)
				mAuthService := new(authMocks.MockAuthService)
				r, err := http.NewRequest("GET", "/auth/verify", nil)
				if err != nil {
					panic(err)
				}
				mAuthorizationMiddleware.On("VerifyToken", mock.Anything).Return(r, nil)
				return mAuthorizationMiddleware, mAuthService, httptest.NewRecorder()
			},
			wantErr: false,
			err:     nil,
		},
		{
			title: "authorization.VerifyToken failed",
			setupMocks: func() (commonInterfaces.AuthorizationMiddleware, authService, http.ResponseWriter) {
				mAuthorizationMiddleware := new(authMocks.MockAuthorizationMiddleware)
				mAuthService := new(authMocks.MockAuthService)
				r, err := http.NewRequest("GET", "/auth/verify", nil)
				if err != nil {
					panic(err)
				}
				mAuthorizationMiddleware.On("VerifyToken", mock.Anything).Return(r, errors.New("failed to process the data"))
				return mAuthorizationMiddleware, mAuthService, httptest.NewRecorder()
			},
			wantErr: true,
			err:     errors.New("failed to process the data"),
		},

		{
			title: "context.DeadlineExceeded",
			setupMocks: func() (commonInterfaces.AuthorizationMiddleware, authService, http.ResponseWriter) {
				mAuthorizationMiddleware := new(authMocks.MockAuthorizationMiddleware)
				mAuthService := new(authMocks.MockAuthService)
				r, err := http.NewRequest("GET", "/auth/verify", nil)
				if err != nil {
					panic(err)
				}
				mAuthorizationMiddleware.On("VerifyToken", mock.Anything).Return(r, context.DeadlineExceeded)
				return mAuthorizationMiddleware, mAuthService, httptest.NewRecorder()
			},
			wantErr: true,
			err:     errors.New("api error: "),
		},
	}

	for _, testScenario := range testsScenarios {
		t.Run(testScenario.title, func(t *testing.T) {
			loggerService := setupAuthControllerDependencies()
			authorizationMiddleware, authService, w := testScenario.setupMocks()
			authController := NewAuthController(loggerService, authService, authorizationMiddleware)

			r, err := http.NewRequest("GET", "/auth/verify", nil)
			if err != nil {
				panic(err)
			}

			err = authController.Verify(w, r)

			if (err != nil) != testScenario.wantErr {
				t.Errorf("Verify() err = %v, wantErr = %v", err, testScenario.wantErr)
			}

			if err != nil && testScenario.err != nil {
				if err.Error() != testScenario.err.Error() {
					t.Errorf("Verify() error = %v, scenarioError = %v", err, testScenario.err)
				}
			}
		})
	}
}

