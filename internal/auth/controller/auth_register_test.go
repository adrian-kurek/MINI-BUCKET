package controller

import (
	"bytes"
	"context"
	"errors"
	"net/http"
	"net/http/httptest"
	"testing"

	authDto "github.com/slodkiadrianek/MINI-BUCKET/internal/auth/DTO"
	commonInterfaces "github.com/slodkiadrianek/MINI-BUCKET/internal/common/interfaces"
	jsonutil "github.com/slodkiadrianek/MINI-BUCKET/internal/common/json_util"
	authMocks "github.com/slodkiadrianek/MINI-BUCKET/test/mocks/auth"
	"github.com/stretchr/testify/mock"
)
func TestRegister(t *testing.T) {
	type args struct {
		title           string
		bodyRequestData authDto.CreateUser
		setupMocks      func() (commonInterfaces.AuthorizationMiddleware, authService, http.ResponseWriter)
		wantErr         bool
		err             error
	}

	testsScenarios := []args{
		{
			title: "with proper data",
			bodyRequestData: authDto.CreateUser{
				Email:           "joeDoe1@gmail.com",
				Password:        "zaq1@#$rfVaaa",
				ConfirmPassword: "zaq1@#$rfVaaa",
				Username:        "joeDoe1",
			},
			setupMocks: func() (commonInterfaces.AuthorizationMiddleware, authService, http.ResponseWriter) {
				mAuthorizationMiddleware := new(authMocks.MockAuthorizationMiddleware)
				mAuthService := new(authMocks.MockAuthService)
				mAuthService.On("Register", mock.Anything, mock.Anything).Return(nil)
				return mAuthorizationMiddleware, mAuthService, httptest.NewRecorder()
			},
			wantErr: false,
			err:     nil,
		},
		{
			title: "ConfirmPassword is not equal to password ",
			bodyRequestData: authDto.CreateUser{
				Email:           "joeDoe1@gmail.com",
				Password:        "zaq1@#$rfVaaa",
				ConfirmPassword: "zaq1@#$rfVaa",
				Username:        "joeDoe1",
			},
			setupMocks: func() (commonInterfaces.AuthorizationMiddleware, authService, http.ResponseWriter) {
				mAuthorizationMiddleware := new(authMocks.MockAuthorizationMiddleware)
				mAuthService := new(authMocks.MockAuthService)
				mAuthService.On("Register", mock.Anything, mock.Anything).Return(nil)
				return mAuthorizationMiddleware, mAuthService, httptest.NewRecorder()
			},
			wantErr: true,
			err:     errors.New("api error: the ConfirmPassword field must be the same as Password field"),
		},
		{
			title: "too weak password",
			bodyRequestData: authDto.CreateUser{
				Email:           "joeDoe1@gmail.com",
				Password:        "zaq1@#$rfVa",
				ConfirmPassword: "zaq1@#$rfVa",
				Username:        "joeDoe1",
			},
			setupMocks: func() (commonInterfaces.AuthorizationMiddleware, authService, http.ResponseWriter) {
				mAuthorizationMiddleware := new(authMocks.MockAuthorizationMiddleware)
				mAuthService := new(authMocks.MockAuthService)
				mAuthService.On("Register", mock.Anything, mock.Anything).Return(nil)
				return mAuthorizationMiddleware, mAuthService, httptest.NewRecorder()
			},
			wantErr: true,
			err:     errors.New("api error: the Password field must be at least 12 characters long"),
		},
		{
			title: "incorrect email format",
			bodyRequestData: authDto.CreateUser{
				Email:           "joeDoe1gmail.com",
				Password:        "zaq1@#$rfVaaa",
				ConfirmPassword: "zaq1@#$rfVaaa",
				Username:        "joeDoe1",
			},
			setupMocks: func() (commonInterfaces.AuthorizationMiddleware, authService, http.ResponseWriter) {
				mAuthorizationMiddleware := new(authMocks.MockAuthorizationMiddleware)
				mAuthService := new(authMocks.MockAuthService)
				mAuthService.On("Register", mock.Anything, mock.Anything).Return(nil)
				return mAuthorizationMiddleware, mAuthService, httptest.NewRecorder()
			},
			wantErr: true,
			err:     errors.New("api error: the Email field must be a valid email address"),
		},
		{
			title: "too short username",
			bodyRequestData: authDto.CreateUser{
				Email:           "joeDoe1@gmail.com",
				Password:        "zaq1@#$rfVaaa",
				ConfirmPassword: "zaq1@#$rfVaaa",
				Username:        "joe",
			},
			setupMocks: func() (commonInterfaces.AuthorizationMiddleware, authService, http.ResponseWriter) {
				mAuthorizationMiddleware := new(authMocks.MockAuthorizationMiddleware)
				mAuthService := new(authMocks.MockAuthService)
				mAuthService.On("Register", mock.Anything, mock.Anything).Return(nil)
				return mAuthorizationMiddleware, mAuthService, httptest.NewRecorder()
			},
			wantErr: true,
			err:     errors.New("api error: the Username field must be at least 6 characters long"),
		},
		{
			title: "authService.Register failed",
			bodyRequestData: authDto.CreateUser{
				Email:           "joeDoe1@gmail.com",
				Password:        "zaq1@#$rfVaaa",
				ConfirmPassword: "zaq1@#$rfVaaa",
				Username:        "joeDoe1",
			},
			setupMocks: func() (commonInterfaces.AuthorizationMiddleware, authService, http.ResponseWriter) {
				mAuthorizationMiddleware := new(authMocks.MockAuthorizationMiddleware)
				mAuthService := new(authMocks.MockAuthService)
				mAuthService.On("Register", mock.Anything, mock.Anything).Return(errors.New("failed to process data"))
				return mAuthorizationMiddleware, mAuthService, httptest.NewRecorder()
			},
			wantErr: true,
			err:     errors.New("failed to process data"),
		},
		{
			title: "context.DeadlineExceeded",
			bodyRequestData: authDto.CreateUser{
				Email:           "joeDoe1@gmail.com",
				Password:        "zaq1@#$rfVaaa",
				ConfirmPassword: "zaq1@#$rfVaaa",
				Username:        "joeDoe1",
			},
			setupMocks: func() (commonInterfaces.AuthorizationMiddleware, authService, http.ResponseWriter) {
				mAuthorizationMiddleware := new(authMocks.MockAuthorizationMiddleware)
				mAuthService := new(authMocks.MockAuthService)
				mAuthService.On("Register", mock.Anything, mock.Anything).Return(context.DeadlineExceeded)
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

			bodyBytes, err := jsonutil.MarshalData(testScenario.bodyRequestData)
			if err != nil {
				panic(err)
			}

			bodyReader := bytes.NewReader(bodyBytes)
			r, err := http.NewRequest("POST", "/auth/register", bodyReader)
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