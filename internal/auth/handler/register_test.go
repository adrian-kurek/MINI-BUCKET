package controller_test

import (
	"bytes"
	"context"
	"errors"
	"net/http"
	"net/http/httptest"
	"testing"

	commonInterfaces "github.com/slodkiadrianek/MINI-BUCKET/common/interfaces"
	jsonutil "github.com/slodkiadrianek/MINI-BUCKET/common/json_util"
	authDTO "github.com/slodkiadrianek/MINI-BUCKET/internal/auth/DTO"
	authHandler "github.com/slodkiadrianek/MINI-BUCKET/internal/auth/handler"
	authMocks "github.com/slodkiadrianek/MINI-BUCKET/test/mocks/auth"
	"github.com/stretchr/testify/mock"
)

func TestRegister(t *testing.T) {
	type args struct {
		title           string
		bodyRequestData authDTO.CreateUser
		setupMocks      func() (commonInterfaces.AuthenticationMiddleware, authHandler.AuthService, http.ResponseWriter)
		wantErr         bool
		err             error
	}

	testsScenarios := []args{
		{
			title: "with proper data",
			bodyRequestData: authDTO.CreateUser{
				Email:           "joeDoe1@gmail.com",
				Password:        "zaq1@#$rfVaaa",
				ConfirmPassword: "zaq1@#$rfVaaa",
				Username:        "joeDoe1",
			},
			setupMocks: func() (commonInterfaces.AuthenticationMiddleware, authHandler.AuthService, http.ResponseWriter) {
				mAuthenticationMiddleware := new(authMocks.MockAuthenticationMiddleware)
				mAuthService := new(authMocks.MockAuthService)
				mAuthService.On("Register", mock.Anything, mock.Anything).Return(nil)
				return mAuthenticationMiddleware, mAuthService, httptest.NewRecorder()
			},
			wantErr: false,
			err:     nil,
		},
		{
			title: "ConfirmPassword is not equal to password ",
			bodyRequestData: authDTO.CreateUser{
				Email:           "joeDoe1@gmail.com",
				Password:        "zaq1@#$rfVaaa",
				ConfirmPassword: "zaq1@#$rfVaa",
				Username:        "joeDoe1",
			},
			setupMocks: func() (commonInterfaces.AuthenticationMiddleware, authHandler.AuthService, http.ResponseWriter) {
				mAuthenticationMiddleware := new(authMocks.MockAuthenticationMiddleware)
				mAuthService := new(authMocks.MockAuthService)
				mAuthService.On("Register", mock.Anything, mock.Anything).Return(nil)
				return mAuthenticationMiddleware, mAuthService, httptest.NewRecorder()
			},
			wantErr: true,
			err:     errors.New("api error: the ConfirmPassword field must be the same as Password field"),
		},
		{
			title: "too weak password",
			bodyRequestData: authDTO.CreateUser{
				Email:           "joeDoe1@gmail.com",
				Password:        "zaq1@#$rfVa",
				ConfirmPassword: "zaq1@#$rfVa",
				Username:        "joeDoe1",
			},
			setupMocks: func() (commonInterfaces.AuthenticationMiddleware, authHandler.AuthService, http.ResponseWriter) {
				mAuthenticationMiddleware := new(authMocks.MockAuthenticationMiddleware)
				mAuthService := new(authMocks.MockAuthService)
				mAuthService.On("Register", mock.Anything, mock.Anything).Return(nil)
				return mAuthenticationMiddleware, mAuthService, httptest.NewRecorder()
			},
			wantErr: true,
			err:     errors.New("api error: the Password field must be at least 12 characters long"),
		},
		{
			title: "incorrect email format",
			bodyRequestData: authDTO.CreateUser{
				Email:           "joeDoe1gmail.com",
				Password:        "zaq1@#$rfVaaa",
				ConfirmPassword: "zaq1@#$rfVaaa",
				Username:        "joeDoe1",
			},
			setupMocks: func() (commonInterfaces.AuthenticationMiddleware, authHandler.AuthService, http.ResponseWriter) {
				mAuthenticationMiddleware := new(authMocks.MockAuthenticationMiddleware)
				mAuthService := new(authMocks.MockAuthService)
				mAuthService.On("Register", mock.Anything, mock.Anything).Return(nil)
				return mAuthenticationMiddleware, mAuthService, httptest.NewRecorder()
			},
			wantErr: true,
			err:     errors.New("api error: the Email field must be a valid email address"),
		},
		{
			title: "too short username",
			bodyRequestData: authDTO.CreateUser{
				Email:           "joeDoe1@gmail.com",
				Password:        "zaq1@#$rfVaaa",
				ConfirmPassword: "zaq1@#$rfVaaa",
				Username:        "joe",
			},
			setupMocks: func() (commonInterfaces.AuthenticationMiddleware, authHandler.AuthService, http.ResponseWriter) {
				mAuthenticationMiddleware := new(authMocks.MockAuthenticationMiddleware)
				mAuthService := new(authMocks.MockAuthService)
				mAuthService.On("Register", mock.Anything, mock.Anything).Return(nil)
				return mAuthenticationMiddleware, mAuthService, httptest.NewRecorder()
			},
			wantErr: true,
			err:     errors.New("api error: the Username field must be at least 6 characters long"),
		},
		{
			title: "authHandler.AuthService.Register failed",
			bodyRequestData: authDTO.CreateUser{
				Email:           "joeDoe1@gmail.com",
				Password:        "zaq1@#$rfVaaa",
				ConfirmPassword: "zaq1@#$rfVaaa",
				Username:        "joeDoe1",
			},
			setupMocks: func() (commonInterfaces.AuthenticationMiddleware, authHandler.AuthService, http.ResponseWriter) {
				mAuthenticationMiddleware := new(authMocks.MockAuthenticationMiddleware)
				mAuthService := new(authMocks.MockAuthService)
				mAuthService.On("Register", mock.Anything, mock.Anything).Return(errors.New("failed to process data"))
				return mAuthenticationMiddleware, mAuthService, httptest.NewRecorder()
			},
			wantErr: true,
			err:     errors.New("failed to process data"),
		},
		{
			title: "context.DeadlineExceeded",
			bodyRequestData: authDTO.CreateUser{
				Email:           "joeDoe1@gmail.com",
				Password:        "zaq1@#$rfVaaa",
				ConfirmPassword: "zaq1@#$rfVaaa",
				Username:        "joeDoe1",
			},
			setupMocks: func() (commonInterfaces.AuthenticationMiddleware, authHandler.AuthService, http.ResponseWriter) {
				mAuthenticationMiddleware := new(authMocks.MockAuthenticationMiddleware)
				mAuthService := new(authMocks.MockAuthService)
				mAuthService.On("Register", mock.Anything, mock.Anything).Return(context.DeadlineExceeded)
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
			authController := authHandler.NewAuthHandler(loggerService, authService, authorizationMiddleware)

			bodyBytes, err := jsonutil.MarshalData(testScenario.bodyRequestData)
			if err != nil {
				panic(err)
			}

			bodyReader := bytes.NewReader(bodyBytes)
			r, err := http.NewRequest(http.MethodPost, "/auth/register", bodyReader)
			if err != nil {
				panic(err)
			}

			err = authController.Register(w, r)

			if (err != nil) != testScenario.wantErr {
				t.Errorf("Register() err = %v, wantErr = %v", err, testScenario.wantErr)
			}

			if err != nil && testScenario.err != nil {
				if err.Error() != testScenario.err.Error() {
					t.Errorf("Register() error = %v, scenarioError = %v", err, testScenario.err)
				}
			}
		})
	}
}
