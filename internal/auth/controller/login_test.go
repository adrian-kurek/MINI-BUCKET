package controller

import (
	"bytes"
	"context"
	"errors"
	"net/http"
	"net/http/httptest"
	"testing"

	commonInterfaces "github.com/slodkiadrianek/MINI-BUCKET/common/interfaces"
	jsonutil "github.com/slodkiadrianek/MINI-BUCKET/common/json_util"
	authDto "github.com/slodkiadrianek/MINI-BUCKET/internal/auth/DTO"
	authMocks "github.com/slodkiadrianek/MINI-BUCKET/test/mocks/auth"
	"github.com/stretchr/testify/mock"
)

func TestLogin(t *testing.T) {
	type args struct {
		title           string
		bodyRequestData authDto.LoginUser
		setupMocks      func() (commonInterfaces.AuthenticationMiddleware, authService, http.ResponseWriter)
		wantErr         bool
		err             error
	}

	testsScenarios := []args{
		{
			title: "with proper data",
			bodyRequestData: authDto.LoginUser{
				Email:    "joeDoe1@gmail.com",
				Password: "zaqwerfdsafsa@!44",
			},
			setupMocks: func() (commonInterfaces.AuthenticationMiddleware, authService, http.ResponseWriter) {
				mAuthenticationMiddleware := new(authMocks.MockAuthenticationMiddleware)
				mAuthService := new(authMocks.MockAuthService)
				mAuthService.On("Login", mock.Anything, mock.Anything, mock.Anything, mock.Anything).Return("12312", []byte("1233445"), nil)
				return mAuthenticationMiddleware, mAuthService, httptest.NewRecorder()
			},
			wantErr: false,
			err:     nil,
		},
		{
			title: "incorrect email format",
			bodyRequestData: authDto.LoginUser{
				Email:    "joeDoe1gmail.com",
				Password: "zaqwerfdsafsa@!44",
			},
			setupMocks: func() (commonInterfaces.AuthenticationMiddleware, authService, http.ResponseWriter) {
				mAuthenticationMiddleware := new(authMocks.MockAuthenticationMiddleware)
				mAuthService := new(authMocks.MockAuthService)
				mAuthService.On("Login", mock.Anything, mock.Anything, mock.Anything, mock.Anything).Return("12312", []byte("1233445"), nil)
				return mAuthenticationMiddleware, mAuthService, httptest.NewRecorder()
			},
			wantErr: true,
			err:     errors.New("api error: the Email field must be a valid email address"),
		},
		{
			title: "authService.Login failed",
			bodyRequestData: authDto.LoginUser{
				Email:    "joeDoe1@gmail.com",
				Password: "zaqwerfdsafsa@!44",
			},
			setupMocks: func() (commonInterfaces.AuthenticationMiddleware, authService, http.ResponseWriter) {
				mAuthenticationMiddleware := new(authMocks.MockAuthenticationMiddleware)
				mAuthService := new(authMocks.MockAuthService)
				mAuthService.On("Login", mock.Anything, mock.Anything, mock.Anything, mock.Anything).Return("", []byte(""), errors.New("failed to process the data"))
				return mAuthenticationMiddleware, mAuthService, httptest.NewRecorder()
			},
			wantErr: true,
			err:     errors.New("failed to process the data"),
		},
		{
			title: "context.DeadlineExceeded",
			bodyRequestData: authDto.LoginUser{
				Email:    "joeDoe1@gmail.com",
				Password: "zaqwerfdsafsa@!44",
			},
			setupMocks: func() (commonInterfaces.AuthenticationMiddleware, authService, http.ResponseWriter) {
				mAuthenticationMiddleware := new(authMocks.MockAuthenticationMiddleware)
				mAuthService := new(authMocks.MockAuthService)
				mAuthService.On("Login", mock.Anything, mock.Anything, mock.Anything, mock.Anything).Return("", []byte(""), context.DeadlineExceeded)
				return mAuthenticationMiddleware, mAuthService, httptest.NewRecorder()
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
			r, err := http.NewRequest("POST", "/auth/login", bodyReader)
			if err != nil {
				panic(err)
			}

			err = authController.Login(w, r)

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