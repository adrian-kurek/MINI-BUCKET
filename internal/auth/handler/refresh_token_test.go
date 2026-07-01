package controller_test

import (
	"context"
	"encoding/hex"
	"errors"
	"net/http"
	"net/http/httptest"
	"testing"

	commonInterfaces "github.com/slodkiadrianek/MINI-BUCKET/common/interfaces"
	authHandler "github.com/slodkiadrianek/MINI-BUCKET/internal/auth/handler"
	authMocks "github.com/slodkiadrianek/MINI-BUCKET/test/mocks/auth"
	"github.com/stretchr/testify/mock"
)

func TestRefreshToken(t *testing.T) {
	type args struct {
		title      string
		setCookie  bool
		setupMocks func() (commonInterfaces.AuthenticationMiddleware, authHandler.AuthService, http.ResponseWriter)
		wantErr    bool
		err        error
	}

	testsScenarios := []args{
		{
			title:     "with proper data",
			setCookie: true,
			setupMocks: func() (commonInterfaces.AuthenticationMiddleware, authHandler.AuthService, http.ResponseWriter) {
				mAuthenticationMiddleware := new(authMocks.MockAuthenticationMiddleware)
				mAuthService := new(authMocks.MockAuthService)
				mAuthService.On("RefreshToken", mock.Anything, mock.Anything).Return("12323232", nil)
				return mAuthenticationMiddleware, mAuthService, httptest.NewRecorder()
			},
			wantErr: false,
			err:     nil,
		},
		{
			title:     "failed to read cookied from request",
			setCookie: false,
			setupMocks: func() (commonInterfaces.AuthenticationMiddleware, authHandler.AuthService, http.ResponseWriter) {
				mAuthenticationMiddleware := new(authMocks.MockAuthenticationMiddleware)
				mAuthService := new(authMocks.MockAuthService)
				mAuthService.On("RefreshToken", mock.Anything, mock.Anything).Return("12323232", nil)
				return mAuthenticationMiddleware, mAuthService, httptest.NewRecorder()
			},
			wantErr: true,
			err:     errors.New("http: named cookie not present"),
		},

		{
			title:     "authHandler.AuthService.RefreshToken failed",
			setCookie: true,
			setupMocks: func() (commonInterfaces.AuthenticationMiddleware, authHandler.AuthService, http.ResponseWriter) {
				mAuthenticationMiddleware := new(authMocks.MockAuthenticationMiddleware)
				mAuthService := new(authMocks.MockAuthService)
				mAuthService.On("RefreshToken", mock.Anything, mock.Anything).
					Return("", errors.New("failed to process data"))
				return mAuthenticationMiddleware, mAuthService, httptest.NewRecorder()
			},
			wantErr: true,
			err:     errors.New("failed to process data"),
		},
		{
			title:     "context.DeadlineExceeded",
			setCookie: true,
			setupMocks: func() (commonInterfaces.AuthenticationMiddleware, authHandler.AuthService, http.ResponseWriter) {
				mAuthenticationMiddleware := new(authMocks.MockAuthenticationMiddleware)
				mAuthService := new(authMocks.MockAuthService)
				mAuthService.On("RefreshToken", mock.Anything, mock.Anything).Return("", context.DeadlineExceeded)
				return mAuthenticationMiddleware, mAuthService, httptest.NewRecorder()
			},
			wantErr: true,
			err:     errors.New("api error: "),
		},
	}

	for _, testScenario := range testsScenarios {
		t.Run(testScenario.title, func(t *testing.T) {
			loggerService := setupAuthHandlerDependencies()
			authorizationMiddleware, authService, w := testScenario.setupMocks()
			h := authHandler.New(loggerService, authService, authorizationMiddleware)

			r, err := http.NewRequest(http.MethodPost, "/auth/login", nil)
			if err != nil {
				panic(err)
			}
			if testScenario.setCookie {
				cookie := http.Cookie{
					Name:  "refreshToken",
					Value: hex.EncodeToString([]byte("1")),
				}
				r.AddCookie(&cookie)
			}

			err = h.RefreshToken(w, r)

			if (err != nil) != testScenario.wantErr {
				t.Errorf("Login() err = %v, wantErr = %v", err, testScenario.wantErr)
			}

			if err != nil && testScenario.err != nil {
				if err.Error() != testScenario.err.Error() {
					t.Errorf("Login() error = %v, scenarioError = %v", err, testScenario.err)
				}
			}
		})
	}
}
