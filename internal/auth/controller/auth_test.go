package controller

import (
	"bytes"
	"context"
	"encoding/hex"
	"errors"
	"fmt"
	"net/http"
	"net/http/httptest"
	"testing"

	authDto "github.com/slodkiadrianek/MINI-BUCKET/internal/auth/DTO"
	commonInterfaces "github.com/slodkiadrianek/MINI-BUCKET/internal/common/interfaces"
	jsonutil "github.com/slodkiadrianek/MINI-BUCKET/internal/common/json_util"
	"github.com/slodkiadrianek/MINI-BUCKET/internal/common/request"
	"github.com/slodkiadrianek/MINI-BUCKET/internal/log"
	authMocks "github.com/slodkiadrianek/MINI-BUCKET/test/mocks/auth"
	"github.com/stretchr/testify/mock"
)

func setupAuthControllerDependencies() *log.Logger {
	loggerService := log.NewLogger("./logs", "2006-01-02", "15:04:05")
	defer func() {
		if closeErr := loggerService.Close(); closeErr != nil {
			fmt.Errorf("failed to properly close file with logs:%s", closeErr.Error())
		}
	}()
	return loggerService
}

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

func TestLogin(t *testing.T) {
	type args struct {
		title           string
		bodyRequestData authDto.LoginUser
		setupMocks      func() (commonInterfaces.AuthorizationMiddleware, authService, http.ResponseWriter)
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
			setupMocks: func() (commonInterfaces.AuthorizationMiddleware, authService, http.ResponseWriter) {
				mAuthorizationMiddleware := new(authMocks.MockAuthorizationMiddleware)
				mAuthService := new(authMocks.MockAuthService)
				mAuthService.On("Login", mock.Anything, mock.Anything, mock.Anything, mock.Anything).Return("12312", []byte("1233445"), nil)
				return mAuthorizationMiddleware, mAuthService, httptest.NewRecorder()
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
			setupMocks: func() (commonInterfaces.AuthorizationMiddleware, authService, http.ResponseWriter) {
				mAuthorizationMiddleware := new(authMocks.MockAuthorizationMiddleware)
				mAuthService := new(authMocks.MockAuthService)
				mAuthService.On("Login", mock.Anything, mock.Anything, mock.Anything, mock.Anything).Return("12312", []byte("1233445"), nil)
				return mAuthorizationMiddleware, mAuthService, httptest.NewRecorder()
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
			setupMocks: func() (commonInterfaces.AuthorizationMiddleware, authService, http.ResponseWriter) {
				mAuthorizationMiddleware := new(authMocks.MockAuthorizationMiddleware)
				mAuthService := new(authMocks.MockAuthService)
				mAuthService.On("Login", mock.Anything, mock.Anything, mock.Anything, mock.Anything).Return("", []byte(""), errors.New("failed to process the data"))
				return mAuthorizationMiddleware, mAuthService, httptest.NewRecorder()
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
			setupMocks: func() (commonInterfaces.AuthorizationMiddleware, authService, http.ResponseWriter) {
				mAuthorizationMiddleware := new(authMocks.MockAuthorizationMiddleware)
				mAuthService := new(authMocks.MockAuthService)
				mAuthService.On("Login", mock.Anything, mock.Anything, mock.Anything, mock.Anything).Return("", []byte(""), context.DeadlineExceeded)
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

func TestRefreshToken(t *testing.T) {
	type args struct {
		title      string
		setCookie  bool
		setupMocks func() (commonInterfaces.AuthorizationMiddleware, authService, http.ResponseWriter)
		wantErr    bool
		err        error
	}

	testsScenarios := []args{
		{
			title:     "with proper data",
			setCookie: true,
			setupMocks: func() (commonInterfaces.AuthorizationMiddleware, authService, http.ResponseWriter) {
				mAuthorizationMiddleware := new(authMocks.MockAuthorizationMiddleware)
				mAuthService := new(authMocks.MockAuthService)
				mAuthService.On("RefreshToken", mock.Anything, mock.Anything).Return("12323232", nil)
				return mAuthorizationMiddleware, mAuthService, httptest.NewRecorder()
			},
			wantErr: false,
			err:     nil,
		},
		{
			title:     "failed to read cookied from request",
			setCookie: false,
			setupMocks: func() (commonInterfaces.AuthorizationMiddleware, authService, http.ResponseWriter) {
				mAuthorizationMiddleware := new(authMocks.MockAuthorizationMiddleware)
				mAuthService := new(authMocks.MockAuthService)
				mAuthService.On("RefreshToken", mock.Anything, mock.Anything).Return("12323232", nil)
				return mAuthorizationMiddleware, mAuthService, httptest.NewRecorder()
			},
			wantErr: true,
			err:     errors.New("http: named cookie not present"),
		},

		{
			title:     "authService.RefreshToken failed",
			setCookie: true,
			setupMocks: func() (commonInterfaces.AuthorizationMiddleware, authService, http.ResponseWriter) {
				mAuthorizationMiddleware := new(authMocks.MockAuthorizationMiddleware)
				mAuthService := new(authMocks.MockAuthService)
				mAuthService.On("RefreshToken", mock.Anything, mock.Anything).Return("", errors.New("failed to process data"))
				return mAuthorizationMiddleware, mAuthService, httptest.NewRecorder()
			},
			wantErr: true,
			err:     errors.New("failed to process data"),
		},
		{
			title:     "context.DeadlineExceeded",
			setCookie: true,
			setupMocks: func() (commonInterfaces.AuthorizationMiddleware, authService, http.ResponseWriter) {
				mAuthorizationMiddleware := new(authMocks.MockAuthorizationMiddleware)
				mAuthService := new(authMocks.MockAuthService)
				mAuthService.On("RefreshToken", mock.Anything, mock.Anything).Return("", context.DeadlineExceeded)
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

			r, err := http.NewRequest("POST", "/auth/login", nil)
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

			err = authController.RefreshToken(w, r)

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

func TestLogoutUser(t *testing.T) {
	type args struct {
		title      string
		setCookie  bool
		setupMocks func() (commonInterfaces.AuthorizationMiddleware, authService, http.ResponseWriter)
		wantErr    bool
		err        error
	}

	testsScenarios := []args{
		{
			title:     "with proper data",
			setCookie: true,
			setupMocks: func() (commonInterfaces.AuthorizationMiddleware, authService, http.ResponseWriter) {
				mAuthorizationMiddleware := new(authMocks.MockAuthorizationMiddleware)
				mAuthService := new(authMocks.MockAuthService)
				mAuthorizationMiddleware.On("BlacklistUser", mock.Anything, mock.Anything).Return(nil)
				mAuthService.On("LogoutUser", mock.Anything, mock.Anything).Return(nil)
				return mAuthorizationMiddleware, mAuthService, httptest.NewRecorder()
			},
			wantErr: false,
			err:     nil,
		},
		{
			title:     "authorization.BlacklistUser failed",
			setCookie: true,
			setupMocks: func() (commonInterfaces.AuthorizationMiddleware, authService, http.ResponseWriter) {
				mAuthorizationMiddleware := new(authMocks.MockAuthorizationMiddleware)
				mAuthService := new(authMocks.MockAuthService)
				mAuthorizationMiddleware.On("BlacklistUser", mock.Anything, mock.Anything).Return(errors.New("failed to process data"))
				return mAuthorizationMiddleware, mAuthService, httptest.NewRecorder()
			},
			wantErr: true,
			err:     errors.New("failed to process data"),
		},
		{
			title:     "authorization.BlacklistUser context.DeadlineExceeded",
			setCookie: true,
			setupMocks: func() (commonInterfaces.AuthorizationMiddleware, authService, http.ResponseWriter) {
				mAuthorizationMiddleware := new(authMocks.MockAuthorizationMiddleware)
				mAuthService := new(authMocks.MockAuthService)
				mAuthorizationMiddleware.On("BlacklistUser", mock.Anything, mock.Anything).Return(context.DeadlineExceeded)
				return mAuthorizationMiddleware, mAuthService, httptest.NewRecorder()
			},
			wantErr: true,
			err:     errors.New("api error: "),
		},
		{
			title:     "failed to read cookie",
			setCookie: false,
			setupMocks: func() (commonInterfaces.AuthorizationMiddleware, authService, http.ResponseWriter) {
				mAuthorizationMiddleware := new(authMocks.MockAuthorizationMiddleware)
				mAuthService := new(authMocks.MockAuthService)
				mAuthorizationMiddleware.On("BlacklistUser", mock.Anything, mock.Anything).Return(nil)
				return mAuthorizationMiddleware, mAuthService, httptest.NewRecorder()
			},
			wantErr: true,
			err:     errors.New("http: named cookie not present"),
		},
		{
			title:     "authService.LogoutUser failed",
			setCookie: true,
			setupMocks: func() (commonInterfaces.AuthorizationMiddleware, authService, http.ResponseWriter) {
				mAuthorizationMiddleware := new(authMocks.MockAuthorizationMiddleware)
				mAuthService := new(authMocks.MockAuthService)
				mAuthorizationMiddleware.On("BlacklistUser", mock.Anything, mock.Anything).Return(nil)
				mAuthService.On("LogoutUser", mock.Anything, mock.Anything).Return(errors.New("failed to process data"))
				return mAuthorizationMiddleware, mAuthService, httptest.NewRecorder()
			},
			wantErr: true,
			err:     errors.New("failed to process data"),
		},
		{
			title:     "authService.LogoutUser context.DeadlineExceeded",
			setCookie: true,
			setupMocks: func() (commonInterfaces.AuthorizationMiddleware, authService, http.ResponseWriter) {
				mAuthorizationMiddleware := new(authMocks.MockAuthorizationMiddleware)
				mAuthService := new(authMocks.MockAuthService)
				mAuthorizationMiddleware.On("BlacklistUser", mock.Anything, mock.Anything).Return(nil)
				mAuthService.On("LogoutUser", mock.Anything, mock.Anything).Return(context.DeadlineExceeded)
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

			r, err := http.NewRequest("DELETE", "/auth/logout", nil)
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

			err = authController.LogoutUser(w, r)

			if (err != nil) != testScenario.wantErr {
				t.Errorf("LogoutUser() err = %v, wantErr = %v", err, testScenario.wantErr)
			}

			if err != nil && testScenario.err != nil {
				if err.Error() != testScenario.err.Error() {
					t.Errorf("LogoutUser() error = %v, scenarioError = %v", err, testScenario.err)
				}
			}
		})
	}
}

func TestLogoutUserFromAllDevices(t *testing.T) {
	type args struct {
		title          string
		setIDInContext bool
		setupMocks     func(setInContext bool) (commonInterfaces.AuthorizationMiddleware, authService, http.ResponseWriter)
		wantErr        bool
		err            error
	}

	testsScenarios := []args{
		{
			title:          "with proper data",
			setIDInContext: true,
			setupMocks: func(setInContext bool) (commonInterfaces.AuthorizationMiddleware, authService, http.ResponseWriter) {
				mAuthorizationMiddleware := new(authMocks.MockAuthorizationMiddleware)
				mAuthService := new(authMocks.MockAuthService)
				r, err := http.NewRequest("DELETE", "/auth/logoutAll", nil)
				if err != nil {
					panic(err)
				}

				if setInContext {
					r = request.SetContext(r, "id", 12)
				}

				mAuthorizationMiddleware.On("VerifyToken", mock.Anything).Return(r, nil)
				mAuthService.On("LogoutUserFromAllDevices", mock.Anything, mock.Anything).Return(nil)
				return mAuthorizationMiddleware, mAuthService, httptest.NewRecorder()
			},
			wantErr: false,
			err:     nil,
		},
		{
			title:          "authorization.VerifyToken failed",
			setIDInContext: true,
			setupMocks: func(setInContext bool) (commonInterfaces.AuthorizationMiddleware, authService, http.ResponseWriter) {
				mAuthorizationMiddleware := new(authMocks.MockAuthorizationMiddleware)
				mAuthService := new(authMocks.MockAuthService)
				r, err := http.NewRequest("GET", "/auth/verify", nil)
				if err != nil {
					panic(err)
				}

				if setInContext {
					r = request.SetContext(r, "id", 12)
				}

				mAuthorizationMiddleware.On("VerifyToken", mock.Anything).Return(r, errors.New("failed to process data"))
				return mAuthorizationMiddleware, mAuthService, httptest.NewRecorder()
			},
			wantErr: true,
			err:     errors.New("failed to process data"),
		},
		{
			title:          "authorization.VerifyToken context.DeadlineExceeded",
			setIDInContext: true,
			setupMocks: func(setInContext bool) (commonInterfaces.AuthorizationMiddleware, authService, http.ResponseWriter) {
				mAuthorizationMiddleware := new(authMocks.MockAuthorizationMiddleware)
				mAuthService := new(authMocks.MockAuthService)
				r, err := http.NewRequest("DELETE", "/auth/logoutAll", nil)
				if err != nil {
					panic(err)
				}

				if setInContext {
					r = request.SetContext(r, "id", 12)
				}

				mAuthorizationMiddleware.On("VerifyToken", mock.Anything).Return(r, context.DeadlineExceeded)
				return mAuthorizationMiddleware, mAuthService, httptest.NewRecorder()
			},
			wantErr: true,
			err:     errors.New("api error: "),
		},
		{
			title:          "failed to read id from token",
			setIDInContext: false,
			setupMocks: func(setInContext bool) (commonInterfaces.AuthorizationMiddleware, authService, http.ResponseWriter) {
				mAuthorizationMiddleware := new(authMocks.MockAuthorizationMiddleware)
				mAuthService := new(authMocks.MockAuthService)
				r, err := http.NewRequest("DELETE", "/auth/logoutAll", nil)
				if err != nil {
					panic(err)
				}

				if setInContext {
					r = request.SetContext(r, "id", 12)
				}

				mAuthorizationMiddleware.On("VerifyToken", mock.Anything).Return(r, nil)
				mAuthService.On("LogoutUserFromAllDevices", mock.Anything, mock.Anything).Return(nil)
				return mAuthorizationMiddleware, mAuthService, httptest.NewRecorder()
			},
			wantErr: true,
			err:     errors.New("failed to read user from context"),
		},
		{
			title:          "authService.LogoutUserFromAllDevices failed",
			setIDInContext: true,
			setupMocks: func(setInContext bool) (commonInterfaces.AuthorizationMiddleware, authService, http.ResponseWriter) {
				mAuthorizationMiddleware := new(authMocks.MockAuthorizationMiddleware)
				mAuthService := new(authMocks.MockAuthService)
				r, err := http.NewRequest("DELETE", "/auth/logoutAll", nil)
				if err != nil {
					panic(err)
				}

				if setInContext {
					r = request.SetContext(r, "id", 12)
				}

				mAuthorizationMiddleware.On("VerifyToken", mock.Anything).Return(r, nil)
				mAuthService.On("LogoutUserFromAllDevices", mock.Anything, mock.Anything).Return(errors.New("failed to process data"))
				return mAuthorizationMiddleware, mAuthService, httptest.NewRecorder()
			},
			wantErr: true,
			err:     errors.New("failed to process data"),
		},
		{
			title:          "authService.LogoutUserFromAllDevices context.DeadlineExceeded",
			setIDInContext: true,
			setupMocks: func(setInContext bool) (commonInterfaces.AuthorizationMiddleware, authService, http.ResponseWriter) {
				mAuthorizationMiddleware := new(authMocks.MockAuthorizationMiddleware)
				mAuthService := new(authMocks.MockAuthService)
				r, err := http.NewRequest("DELETE", "/auth/logoutAll", nil)
				if err != nil {
					panic(err)
				}

				if setInContext {
					r = request.SetContext(r, "id", 12)
				}

				mAuthorizationMiddleware.On("VerifyToken", mock.Anything).Return(r, nil)
				mAuthService.On("LogoutUserFromAllDevices", mock.Anything, mock.Anything).Return(context.DeadlineExceeded)
				return mAuthorizationMiddleware, mAuthService, httptest.NewRecorder()
			},
			wantErr: true,
			err:     errors.New("api error: "),
		},
	}

	for _, testScenario := range testsScenarios {
		t.Run(testScenario.title, func(t *testing.T) {
			loggerService := setupAuthControllerDependencies()
			authorizationMiddleware, authService, w := testScenario.setupMocks(testScenario.setIDInContext)
			authController := NewAuthController(loggerService, authService, authorizationMiddleware)

			r, err := http.NewRequest("DELETE", "/auth/logoutAll", nil)
			if err != nil {
				panic(err)
			}

			err = authController.LogoutUserFromAllDevices(w, r)

			if (err != nil) != testScenario.wantErr {
				t.Errorf("LogoutUserFromAllDevices() err = %v, wantErr = %v", err, testScenario.wantErr)
			}

			if err != nil && testScenario.err != nil {
				if err.Error() != testScenario.err.Error() {
					t.Errorf("LogoutUserFromAllDevices() error = %v, scenarioError = %v", err, testScenario.err)
				}
			}
		})
	}
}

func TestActivateAccount(t *testing.T) {
	type args struct {
		title string
		token string
		setupMocks func() (commonInterfaces.AuthorizationMiddleware, authService, http.ResponseWriter)
		wantErr bool
		err error
	}

	testsScenarios := []args{
		{
			title: "with proper data",
			token: "123123123123123123123123123123",
			setupMocks: func() (commonInterfaces.AuthorizationMiddleware, authService, http.ResponseWriter) {
				mAuthorizationMiddleware := new(authMocks.MockAuthorizationMiddleware)
				mAuthService := new(authMocks.MockAuthService)
				r, err := http.NewRequest("GET", "/auth/activate?token=123123123123123123123123123123", nil)
				if err != nil {
					panic(err)
				}

				r = request.SetContext(r, "id", 1)
				mAuthorizationMiddleware.On("VerifyToken", mock.Anything).Return(r, nil)
				mAuthService.On("ActivateAccount", mock.Anything,mock.Anything).Return(nil)
				return mAuthorizationMiddleware, mAuthService, httptest.NewRecorder()
			},
			wantErr: false,
			err:     nil,	
		},
		{
			title: "authorization.VerifyToken() context.DeadlineExceeded",
			token: "123123123123123123123123123123",
			setupMocks: func() (commonInterfaces.AuthorizationMiddleware, authService, http.ResponseWriter) {
				mAuthorizationMiddleware := new(authMocks.MockAuthorizationMiddleware)
				mAuthService := new(authMocks.MockAuthService)
				r, err := http.NewRequest("GET", "/auth/activate?token=123123123123123123123123123123", nil)
				if err != nil {
					panic(err)
				}

				r = request.SetContext(r, "id", 1)
				mAuthorizationMiddleware.On("VerifyToken", mock.Anything).Return(r, context.DeadlineExceeded)
				mAuthService.On("ActivateAccount", mock.Anything,mock.Anything).Return(nil)
				return mAuthorizationMiddleware, mAuthService, httptest.NewRecorder()
			},
			wantErr: true,
			err:     errors.New("api error: "),	
		},
		{
			title: "authorization.VerifyToken() failed",
			token: "123123123123123123123123123123",
			setupMocks: func() (commonInterfaces.AuthorizationMiddleware, authService, http.ResponseWriter) {
				mAuthorizationMiddleware := new(authMocks.MockAuthorizationMiddleware)
				mAuthService := new(authMocks.MockAuthService)
				r, err := http.NewRequest("GET", "/auth/activate?token=123123123123123123123123123123", nil)
				if err != nil {
					panic(err)
				}

				r = request.SetContext(r, "id", 1)
				mAuthorizationMiddleware.On("VerifyToken", mock.Anything).Return(r, errors.New("failed to process data"))
				mAuthService.On("ActivateAccount", mock.Anything,mock.Anything).Return(nil)
				return mAuthorizationMiddleware, mAuthService, httptest.NewRecorder()
			},
			wantErr: true,
			err:     errors.New("failed to process data"),	
		},
		{
			title: "authService.ActivateAccount() failed",
			token: "123123123123123123123123123123",
			setupMocks: func() (commonInterfaces.AuthorizationMiddleware, authService, http.ResponseWriter) {
				mAuthorizationMiddleware := new(authMocks.MockAuthorizationMiddleware)
				mAuthService := new(authMocks.MockAuthService)
				r, err := http.NewRequest("GET", "/auth/activate?token=123123123123123123123123123123", nil)
				if err != nil {
					panic(err)
				}

				r = request.SetContext(r, "id", 1)
				mAuthorizationMiddleware.On("VerifyToken", mock.Anything).Return(r, nil)
				mAuthService.On("ActivateAccount", mock.Anything,mock.Anything).Return(errors.New("failed to process data"))	
				return mAuthorizationMiddleware, mAuthService, httptest.NewRecorder()
			},
			wantErr: true,
			err:     errors.New("failed to process data"),	
		},
		{
			title: "authService.ActivateAccount() context.DeadlineExceeded",
			token: "123123123123123123123123123123",
			setupMocks: func() (commonInterfaces.AuthorizationMiddleware, authService, http.ResponseWriter) {
				mAuthorizationMiddleware := new(authMocks.MockAuthorizationMiddleware)
				mAuthService := new(authMocks.MockAuthService)
				r, err := http.NewRequest("GET", "/auth/activate?token=123123123123123123123123123123", nil)
				if err != nil {
					panic(err)
				}

				r = request.SetContext(r, "id", 1)
				mAuthorizationMiddleware.On("VerifyToken", mock.Anything).Return(r, nil)
				mAuthService.On("ActivateAccount", mock.Anything,mock.Anything).Return(context.DeadlineExceeded)	
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

			r, err := http.NewRequest("GET", "/auth/activate?token="+testScenario.token, nil)
			if err != nil {
				panic(err)
			}

			err = authController.ActivateAccount(w, r)

			if (err != nil) != testScenario.wantErr {
				t.Errorf("ActivateAccount() err = %v, wantErr = %v", err, testScenario.wantErr)
			}

			if err != nil && testScenario.err != nil {
				if err.Error() != testScenario.err.Error() {
					t.Errorf("ActivateAccount() error = %v, scenarioError = %v", err, testScenario.err)
				}
			}
		})
	}
}