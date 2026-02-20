package service

import (
	"context"
	"errors"
	"fmt"
	"testing"
	"time"

	authDto "github.com/slodkiadrianek/MINI-BUCKET/internal/auth/DTO"
	authModel "github.com/slodkiadrianek/MINI-BUCKET/internal/auth/model"
	"github.com/slodkiadrianek/MINI-BUCKET/internal/common/interfaces"
	"github.com/slodkiadrianek/MINI-BUCKET/internal/log"
	"github.com/slodkiadrianek/MINI-BUCKET/internal/user/model"
	"github.com/slodkiadrianek/MINI-BUCKET/test/mocks"
	"github.com/stretchr/testify/mock"
)

func setupAuthServiceDependencies() *log.Logger {
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
		title     string
		user      authDto.CreateUser
		setupMock func() (authRepository, interfaces.UserRepository, interfaces.AuthorizationMiddleware)
		wantErr   bool
		err       error
	}
	testsScenarios := []args{
		{
			title: "with proper data",
			user: authDto.CreateUser{
				Username:        "joeDoe",
				Email:           "joedoe@gmail.com",
				Password:        "zaq1@#$rfvbgt5",
				ConfirmPassword: "zaq1@#$rfvbgt5",
			},
			setupMock: func() (authRepository, interfaces.UserRepository, interfaces.AuthorizationMiddleware) {
				mAuthRepository := new(mocks.MockAuthRepository)
				mUserRepository := new(mocks.MockUserRepository)
				mAuthorizationMiddleware := new(mocks.MockAuthorizationMiddleware)
				mUserRepository.On("FindUserByEmail", mock.Anything, mock.Anything).Return(model.User{
					ID: 0,
				}, nil)
				mAuthRepository.On("RegisterUser", mock.Anything, mock.Anything, mock.Anything).Return(nil)
				return mAuthRepository, mUserRepository, mAuthorizationMiddleware
			},
			wantErr: false,
			err:     nil,
		},
		{
			title: "user with provided email already exists",
			user: authDto.CreateUser{
				Username:        "joeDoe",
				Email:           "joedoe@gmail.com",
				Password:        "zaq1@#$rfvbgt5",
				ConfirmPassword: "zaq1@#$rfvbgt5",
			},
			setupMock: func() (authRepository, interfaces.UserRepository, interfaces.AuthorizationMiddleware) {
				mAuthRepository := new(mocks.MockAuthRepository)
				mUserRepository := new(mocks.MockUserRepository)
				mAuthorizationMiddleware := new(mocks.MockAuthorizationMiddleware)
				mUserRepository.On("FindUserByEmail", mock.Anything, mock.Anything).Return(model.User{
					ID: 1,
				}, nil)
				mAuthRepository.On("RegisterUser", mock.Anything, mock.Anything, mock.Anything).Return(nil)
				return mAuthRepository, mUserRepository, mAuthorizationMiddleware
			},
			wantErr: true,
			err:     errors.New("api error: user with provided email already exists"),
		},
		{
			title: "FindUserByEmail failed",
			user: authDto.CreateUser{
				Username:        "joeDoe",
				Email:           "joedoe@gmail.com",
				Password:        "zaq1@#$rfvbgt5",
				ConfirmPassword: "zaq1@#$rfvbgt5",
			},
			setupMock: func() (authRepository, interfaces.UserRepository, interfaces.AuthorizationMiddleware) {
				mAuthRepository := new(mocks.MockAuthRepository)
				mUserRepository := new(mocks.MockUserRepository)
				mAuthorizationMiddleware := new(mocks.MockAuthorizationMiddleware)
				mUserRepository.On("FindUserByEmail", mock.Anything, mock.Anything).Return(model.User{}, errors.New("failed to find user by email"))
				mAuthRepository.On("RegisterUser", mock.Anything, mock.Anything, mock.Anything).Return(nil)
				return mAuthRepository, mUserRepository, mAuthorizationMiddleware
			},
			wantErr: true,
			err:     errors.New("failed to find user by email"),
		},
		{
			title: "RegisterUser failed",
			user: authDto.CreateUser{
				Username:        "joeDoe",
				Email:           "joedoe@gmail.com",
				Password:        "zaq1@#$rfvbgt5",
				ConfirmPassword: "zaq1@#$rfvbgt5",
			},
			setupMock: func() (authRepository, interfaces.UserRepository, interfaces.AuthorizationMiddleware) {
				mAuthRepository := new(mocks.MockAuthRepository)
				mUserRepository := new(mocks.MockUserRepository)
				mAuthorizationMiddleware := new(mocks.MockAuthorizationMiddleware)
				mUserRepository.On("FindUserByEmail", mock.Anything, mock.Anything).Return(model.User{
					ID: 0,
				}, nil)
				mAuthRepository.On("RegisterUser", mock.Anything, mock.Anything, mock.Anything).Return(errors.New("failed to insert user to DB"))
				return mAuthRepository, mUserRepository, mAuthorizationMiddleware
			},
			wantErr: true,
			err:     errors.New("failed to insert user to DB"),
		},
	}

	for _, testScenario := range testsScenarios {
		t.Run(testScenario.title, func(t *testing.T) {
			ctx, cancel := context.WithTimeout(context.Background(), 2*time.Second)
			defer cancel()

			authRepository, userRepository, authorizationMiddleware := testScenario.setupMock()
			loggerService := setupAuthServiceDependencies()
			authService := NewAuthService(loggerService, userRepository, authRepository, authorizationMiddleware)

			err := authService.Register(ctx, testScenario.user)

			if (err != nil) != testScenario.wantErr {
				t.Errorf("Register() error = %v, wantErr = %v", err, testScenario.wantErr)
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
		title     string
		user      authDto.LoginUser
		setupMock func() (authRepository, interfaces.UserRepository, interfaces.AuthorizationMiddleware)
		wantErr   bool
		err       error
	}

	testsScenarios := []args{
		{
			title: "with proper data",
			user: authDto.LoginUser{
				Email:    "joedoe@gmail.com",
				Password: "zasfsafds@#!sdwe32",
			},
			setupMock: func() (authRepository, interfaces.UserRepository, interfaces.AuthorizationMiddleware) {
				mAuthRepository := new(mocks.MockAuthRepository)
				mUserRepository := new(mocks.MockUserRepository)
				mAuthorizationMiddleware := new(mocks.MockAuthorizationMiddleware)
				mAuthRepository.On("InsertRefreshToken", mock.Anything, mock.Anything, mock.Anything, mock.Anything, mock.Anything).Return(nil)
				mUserRepository.On("FindUserByEmail",  mock.Anything, mock.Anything).Return(model.User{
					ID: 1,
					EmailVerified: true,
					Password:"$2a$12$uqfZc1qMbaeN2HKUQhY6SOimGPw6j6Vam6njGSJfbz.bghZGAwkOK",
				},nil)
				mAuthorizationMiddleware.On("GenerateAccessToken", mock.Anything).Return("123245", nil)
				mAuthorizationMiddleware.On("GenerateRefreshToken").Return([]byte("2324242"),nil)
				mAuthorizationMiddleware.On("HashToken", mock.Anything).Return("12345")

				return mAuthRepository, mUserRepository, mAuthorizationMiddleware
			},
			wantErr: false,
			err: nil,
		},
		{
			title: "FindUserByEmail failed",
			user: authDto.LoginUser{
				Email:    "joedoe@gmail.com",
				Password: "zasfsafds@#!sdwe32",
			},
			setupMock: func() (authRepository, interfaces.UserRepository, interfaces.AuthorizationMiddleware) {
				mAuthRepository := new(mocks.MockAuthRepository)
				mUserRepository := new(mocks.MockUserRepository)
				mAuthorizationMiddleware := new(mocks.MockAuthorizationMiddleware)
				mUserRepository.On("FindUserByEmail",  mock.Anything, mock.Anything).Return(model.User{},errors.New("failed to get user from DB"))
				return mAuthRepository, mUserRepository, mAuthorizationMiddleware
			},
			wantErr: true,
			err: errors.New("failed to get user from DB"),
		},
		{
			title: "user with provided email not found",
			user: authDto.LoginUser{
				Email:    "joedoe@gmail.com",
				Password: "zasfsafds@#!sdwe32",
			},
			setupMock: func() (authRepository, interfaces.UserRepository, interfaces.AuthorizationMiddleware) {
				mAuthRepository := new(mocks.MockAuthRepository)
				mUserRepository := new(mocks.MockUserRepository)
				mAuthorizationMiddleware := new(mocks.MockAuthorizationMiddleware)
				mUserRepository.On("FindUserByEmail",  mock.Anything, mock.Anything).Return(model.User{
					ID: 0,
				},nil)

				return mAuthRepository, mUserRepository, mAuthorizationMiddleware
			},
			wantErr: true,
			err: errors.New("api error: user with provided email not found"),
		},
		{
			title: "user with provided email is not verified",
			user: authDto.LoginUser{
				Email:    "joedoe@gmail.com",
				Password: "zasfsafds@#!sdwe32",
			},
			setupMock: func() (authRepository, interfaces.UserRepository, interfaces.AuthorizationMiddleware) {
				mAuthRepository := new(mocks.MockAuthRepository)
				mUserRepository := new(mocks.MockUserRepository)
				mAuthorizationMiddleware := new(mocks.MockAuthorizationMiddleware)
				mUserRepository.On("FindUserByEmail",  mock.Anything, mock.Anything).Return(model.User{
					EmailVerified: false,
					ID: 1,
				},nil)

				return mAuthRepository, mUserRepository, mAuthorizationMiddleware
			},
			wantErr: true,
			err: errors.New("api error: user with provided email is not verified"),
		},
		{
			title: "provided incorrect password",
			user: authDto.LoginUser{
				Email:    "joedoe@gmail.com",
				Password: "zasfsafds@#!sdwe37",
			},
			setupMock: func() (authRepository, interfaces.UserRepository, interfaces.AuthorizationMiddleware) {
				mAuthRepository := new(mocks.MockAuthRepository)
				mUserRepository := new(mocks.MockUserRepository)
				mAuthorizationMiddleware := new(mocks.MockAuthorizationMiddleware)
				mUserRepository.On("FindUserByEmail",  mock.Anything, mock.Anything).Return(model.User{
					ID: 1,
					EmailVerified: true,
					Password:"$2a$12$uqfZc1qMbaeN2HKUQhY6SOimGPw6j6Vam6njGSJfbz.bghZGAwkOK",
				},nil)

				return mAuthRepository, mUserRepository, mAuthorizationMiddleware
			},
			wantErr: true,
			err: errors.New("api error: provided incorrect password"),
		},
		{
			title: "GenerateAccessToken failed",
			user: authDto.LoginUser{
				Email:    "joedoe@gmail.com",
				Password: "zasfsafds@#!sdwe32",
			},
			setupMock: func() (authRepository, interfaces.UserRepository, interfaces.AuthorizationMiddleware) {
				mAuthRepository := new(mocks.MockAuthRepository)
				mUserRepository := new(mocks.MockUserRepository)
				mAuthorizationMiddleware := new(mocks.MockAuthorizationMiddleware)
				mUserRepository.On("FindUserByEmail",  mock.Anything, mock.Anything).Return(model.User{
					ID: 1,
					EmailVerified: true,
					Password:"$2a$12$uqfZc1qMbaeN2HKUQhY6SOimGPw6j6Vam6njGSJfbz.bghZGAwkOK",
				},nil)
				mAuthorizationMiddleware.On("GenerateAccessToken", mock.Anything).Return("", errors.New("failed to generate new access token"))

				return mAuthRepository, mUserRepository, mAuthorizationMiddleware
			},
			wantErr: true,
			err: errors.New("failed to generate new access token"),
		},
		{
			title: "GenerateRefreshToken failed",
			user: authDto.LoginUser{
				Email:    "joedoe@gmail.com",
				Password: "zasfsafds@#!sdwe32",
			},
			setupMock: func() (authRepository, interfaces.UserRepository, interfaces.AuthorizationMiddleware) {
				mAuthRepository := new(mocks.MockAuthRepository)
				mUserRepository := new(mocks.MockUserRepository)
				mAuthorizationMiddleware := new(mocks.MockAuthorizationMiddleware)
				mUserRepository.On("FindUserByEmail",  mock.Anything, mock.Anything).Return(model.User{
					ID: 1,
					EmailVerified: true,
					Password:"$2a$12$uqfZc1qMbaeN2HKUQhY6SOimGPw6j6Vam6njGSJfbz.bghZGAwkOK",
				},nil)
				mAuthorizationMiddleware.On("GenerateAccessToken", mock.Anything).Return("123245", nil)
				mAuthorizationMiddleware.On("GenerateRefreshToken").Return([]byte("2324242"),errors.New("failed to generate new refresh token"))

				return mAuthRepository, mUserRepository, mAuthorizationMiddleware
			},
			wantErr: true,
			err: errors.New("failed to generate new refresh token"),
		},
		{
			title: "InsertRefreshToken failed",
			user: authDto.LoginUser{
				Email:    "joedoe@gmail.com",
				Password: "zasfsafds@#!sdwe32",
			},
			setupMock: func() (authRepository, interfaces.UserRepository, interfaces.AuthorizationMiddleware) {
				mAuthRepository := new(mocks.MockAuthRepository)
				mUserRepository := new(mocks.MockUserRepository)
				mAuthorizationMiddleware := new(mocks.MockAuthorizationMiddleware)
				mAuthRepository.On("InsertRefreshToken", mock.Anything, mock.Anything, mock.Anything, mock.Anything, mock.Anything).Return(errors.New("failed to insert refresh token to DB"))
				mUserRepository.On("FindUserByEmail",  mock.Anything, mock.Anything).Return(model.User{
					ID: 1,
					EmailVerified: true,
					Password:"$2a$12$uqfZc1qMbaeN2HKUQhY6SOimGPw6j6Vam6njGSJfbz.bghZGAwkOK",
				},nil)
				mAuthorizationMiddleware.On("GenerateAccessToken", mock.Anything).Return("123245", nil)
				mAuthorizationMiddleware.On("GenerateRefreshToken").Return([]byte("2324242"),nil)
				mAuthorizationMiddleware.On("HashToken", mock.Anything).Return("12345")

				return mAuthRepository, mUserRepository, mAuthorizationMiddleware
			},
			wantErr: true,
			err: errors.New("failed to insert refresh token to DB"),
		},
	}

	for _, testScenario := range testsScenarios {
		t.Run(testScenario.title, func (t *testing.T){
			ctx, cancel := context.WithTimeout(context.Background(), 2*time.Second)
			defer cancel()

			authRepository, userRepository, authorizationMiddleware := testScenario.setupMock()
			loggerService := setupAuthServiceDependencies()
			authService := NewAuthService(loggerService, userRepository, authRepository, authorizationMiddleware)

			ipAddress := "127.0.0.1:2137"
			deviceInfo:= "Apple computer"

			_,_,err := authService.Login(ctx, testScenario.user, ipAddress,deviceInfo)
			if (err != nil) != testScenario.wantErr{
				t.Errorf("Login() error = %v, wantErr = %v", err, testScenario.wantErr)
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
		title     string
		refreshToken []byte
		setupMock func() (authRepository, interfaces.UserRepository, interfaces.AuthorizationMiddleware)
		wantErr   bool
		err       error
	}
	testsScenarios := []args{
		{
			title: "with proper data",
			refreshToken: []byte("123456789"),
			setupMock: func() (authRepository, interfaces.UserRepository, interfaces.AuthorizationMiddleware) {
				mAuthRepository := new(mocks.MockAuthRepository)
				mAuthorizationMiddleware := new(mocks.MockAuthorizationMiddleware)
				mUserRepository := new(mocks.MockUserRepository)
				mAuthorizationMiddleware.On("HashToken", mock.Anything).Return("abcdef")
				mAuthRepository.On("GetRefreshTokenByTokenHash", mock.Anything, mock.Anything).Return(authModel.TokenWithUserEmailToRefreshToken{
					ID: 1,
					ExpiresAt: time.Now().Add(10*time.Minute),
				},nil)
				mAuthRepository.On("UpdateLastTimeUsedToken", mock.Anything, mock.Anything).Return(nil)
				mAuthorizationMiddleware.On("GenerateAccessToken", mock.Anything).Return("123456", nil)
				return mAuthRepository,  mUserRepository, mAuthorizationMiddleware
			},
			wantErr: false,
			err: nil,
		},
		{
			title: "GetRefreshTokenByTokenHash failed",
			refreshToken: []byte("123456789"),
			setupMock: func() (authRepository, interfaces.UserRepository, interfaces.AuthorizationMiddleware) {
				mAuthRepository := new(mocks.MockAuthRepository)
				mAuthorizationMiddleware := new(mocks.MockAuthorizationMiddleware)
				mUserRepository := new(mocks.MockUserRepository)
				mAuthorizationMiddleware.On("HashToken", mock.Anything).Return("abcdef")
				mAuthRepository.On("GetRefreshTokenByTokenHash", mock.Anything, mock.Anything).Return(authModel.TokenWithUserEmailToRefreshToken{},errors.New("failed to get token from DB"))
				return mAuthRepository,  mUserRepository, mAuthorizationMiddleware
			},
			wantErr: true,
			err: errors.New("failed to get token from DB"),
		},
		{
			title: "token not found",
			refreshToken: []byte("123456789"),
			setupMock: func() (authRepository, interfaces.UserRepository, interfaces.AuthorizationMiddleware) {
				mAuthRepository := new(mocks.MockAuthRepository)
				mAuthorizationMiddleware := new(mocks.MockAuthorizationMiddleware)
				mUserRepository := new(mocks.MockUserRepository)
				mAuthorizationMiddleware.On("HashToken", mock.Anything).Return("abcdef")
				mAuthRepository.On("GetRefreshTokenByTokenHash", mock.Anything, mock.Anything).Return(authModel.TokenWithUserEmailToRefreshToken{
					ID: 0,
				},nil)
				return mAuthRepository,  mUserRepository, mAuthorizationMiddleware
			},
			wantErr: true,
			err: errors.New("api error: token not found"),
		},
		{
			title: "refresh token expired",
			refreshToken: []byte("123456789"),
			setupMock: func() (authRepository, interfaces.UserRepository, interfaces.AuthorizationMiddleware) {
				mAuthRepository := new(mocks.MockAuthRepository)
				mAuthorizationMiddleware := new(mocks.MockAuthorizationMiddleware)
				mUserRepository := new(mocks.MockUserRepository)
				mAuthorizationMiddleware.On("HashToken", mock.Anything).Return("abcdef")
				mAuthRepository.On("GetRefreshTokenByTokenHash", mock.Anything, mock.Anything).Return(authModel.TokenWithUserEmailToRefreshToken{
					ID: 1,
					ExpiresAt: time.Now().Add(-2 * time.Minute),
				},nil)
				return mAuthRepository,  mUserRepository, mAuthorizationMiddleware
			},
			wantErr: true,
			err: errors.New("api error: refresh token expired"),
		},
		{
			title: "UpdateLastTimeUsedToken failed",
			refreshToken: []byte("123456789"),
			setupMock: func() (authRepository, interfaces.UserRepository, interfaces.AuthorizationMiddleware) {
				mAuthRepository := new(mocks.MockAuthRepository)
				mAuthorizationMiddleware := new(mocks.MockAuthorizationMiddleware)
				mUserRepository := new(mocks.MockUserRepository)
				mAuthorizationMiddleware.On("HashToken", mock.Anything).Return("abcdef")
				mAuthRepository.On("GetRefreshTokenByTokenHash", mock.Anything, mock.Anything).Return(authModel.TokenWithUserEmailToRefreshToken{
					ID: 1,
					ExpiresAt: time.Now().Add(10*time.Minute),
				},nil)
				mAuthRepository.On("UpdateLastTimeUsedToken", mock.Anything, mock.Anything).Return(errors.New("failed to update last time used token"))
				// mAuthorizationMiddleware.On("GenerateAccessToken", mock.Anything).Return("123456", nil)
				return mAuthRepository,  mUserRepository, mAuthorizationMiddleware
			},
			wantErr: true,
			err: errors.New("failed to update last time used token"),
		},
		{
			title: "GenerateAccessToken failed",
			refreshToken: []byte("123456789"),
			setupMock: func() (authRepository, interfaces.UserRepository, interfaces.AuthorizationMiddleware) {
				mAuthRepository := new(mocks.MockAuthRepository)
				mAuthorizationMiddleware := new(mocks.MockAuthorizationMiddleware)
				mUserRepository := new(mocks.MockUserRepository)
				mAuthorizationMiddleware.On("HashToken", mock.Anything).Return("abcdef")
				mAuthRepository.On("GetRefreshTokenByTokenHash", mock.Anything, mock.Anything).Return(authModel.TokenWithUserEmailToRefreshToken{
					ID: 1,
					ExpiresAt: time.Now().Add(10*time.Minute),
				},nil)
				mAuthRepository.On("UpdateLastTimeUsedToken", mock.Anything, mock.Anything).Return(nil)
				mAuthorizationMiddleware.On("GenerateAccessToken", mock.Anything).Return("", errors.New("failed to generate new access token"))
				return mAuthRepository,  mUserRepository, mAuthorizationMiddleware
			},
			wantErr: true,
			err: errors.New("failed to generate new access token"),
		},
	}

	for _, testScenario := range testsScenarios{
		t.Run(testScenario.title, func(t *testing.T){

			ctx, cancel := context.WithTimeout(context.Background(), 2*time.Second)
			defer cancel()

			authRepository, userRepository, authorizationMiddleware := testScenario.setupMock()
			loggerService := setupAuthServiceDependencies()
			authService := NewAuthService(loggerService, userRepository, authRepository, authorizationMiddleware)


			_,err := authService.RefreshToken(ctx, testScenario.refreshToken)
			if (err != nil) != testScenario.wantErr{
				t.Errorf("RefreshToken() error = %v, wantErr = %v", err, testScenario.wantErr)
			}

			if err != nil && testScenario.err != nil {
				if err.Error() != testScenario.err.Error() {
					t.Errorf("RefreshToken() error = %v, scenarioError = %v", err, testScenario.err)
				}
			}

		})
	}
}


func TestLogoutUser(t *testing.T) {
	type args struct {
		title     string
		setupMock func() (authRepository, interfaces.UserRepository, interfaces.AuthorizationMiddleware)
		wantErr   bool
		err       error
	}

	testsScenarios := []args{
		{
			title: "with proper data",

			setupMock: func() (authRepository, interfaces.UserRepository, interfaces.AuthorizationMiddleware) {
				mAuthRepository := new(mocks.MockAuthRepository)
				mAuthorizationMiddleware := new(mocks.MockAuthorizationMiddleware)
				mUserRepository := new(mocks.MockUserRepository)

				mAuthorizationMiddleware.On("HashToken",mock.Anything).Return("12345")
				mAuthRepository.On("RemoveTokenFromDB", mock.Anything, mock.Anything).Return(nil)				
				return mAuthRepository, mUserRepository, mAuthorizationMiddleware
			},
			wantErr: false,
			err: nil,
		},
		{
			title: "RemoveTokenFromDB failed",

			setupMock: func() (authRepository, interfaces.UserRepository, interfaces.AuthorizationMiddleware) {
				mAuthRepository := new(mocks.MockAuthRepository)
				mAuthorizationMiddleware := new(mocks.MockAuthorizationMiddleware)
				mUserRepository := new(mocks.MockUserRepository)

				mAuthorizationMiddleware.On("HashToken",mock.Anything).Return("12345")
				mAuthRepository.On("RemoveTokenFromDB", mock.Anything, mock.Anything).Return(errors.New("failed to remove token from DB"))
				return mAuthRepository, mUserRepository, mAuthorizationMiddleware
			},
			wantErr: true,
			err: errors.New("failed to remove token from DB"),
		},
	}

	for _, testScenario := range testsScenarios{
		t.Run(testScenario.title, func(t *testing.T){

			ctx, cancel := context.WithTimeout(context.Background(), 2*time.Second)
			defer cancel()

			authRepository, userRepository, authorizationMiddleware := testScenario.setupMock()
			loggerService := setupAuthServiceDependencies()
			authService := NewAuthService(loggerService, userRepository, authRepository, authorizationMiddleware)


			err := authService.LogoutUser(ctx, []byte("123456"))
			if (err != nil) != testScenario.wantErr{
				t.Errorf("RefreshToken() error = %v, wantErr = %v", err, testScenario.wantErr)
			}

			if err != nil && testScenario.err != nil {
				if err.Error() != testScenario.err.Error() {
					t.Errorf("RefreshToken() error = %v, scenarioError = %v", err, testScenario.err)
				}
			}

		})
	}
}


func TestLogoutUserFromAllDevices(t *testing.T){
	type args struct {
		title     string
		setupMock func() (authRepository, interfaces.UserRepository, interfaces.AuthorizationMiddleware)
		wantErr   bool
		err       error
	}

	testsScenarios := []args{
		{
			title: "with proper data",
			setupMock: func() (authRepository, interfaces.UserRepository, interfaces.AuthorizationMiddleware) {
				mAuthRepository := new(mocks.MockAuthRepository)
				mAuthorizationMiddleware := new(mocks.MockAuthorizationMiddleware)
				mUserRepository := new(mocks.MockUserRepository)

				mAuthRepository.On("RemoveTokensFromDBByUserID", mock.Anything, mock.Anything).Return(nil)				
				return mAuthRepository, mUserRepository, mAuthorizationMiddleware
			},
			wantErr: false,
			err: nil,
		},
		{
			title: "RemoveTokenFromDB failed",

			setupMock: func() (authRepository, interfaces.UserRepository, interfaces.AuthorizationMiddleware) {
				mAuthRepository := new(mocks.MockAuthRepository)
				mAuthorizationMiddleware := new(mocks.MockAuthorizationMiddleware)
				mUserRepository := new(mocks.MockUserRepository)

				mAuthRepository.On("RemoveTokensFromDBByUserID", mock.Anything, mock.Anything).Return(errors.New("failed to remove token from DB"))
				return mAuthRepository, mUserRepository, mAuthorizationMiddleware
			},
			wantErr: true,
			err: errors.New("failed to remove token from DB"),
		},
	}

	for _, testScenario := range testsScenarios{
		t.Run(testScenario.title, func(t *testing.T){

			ctx, cancel := context.WithTimeout(context.Background(), 2*time.Second)
			defer cancel()

			authRepository, userRepository, authorizationMiddleware := testScenario.setupMock()
			loggerService := setupAuthServiceDependencies()
			authService := NewAuthService(loggerService, userRepository, authRepository, authorizationMiddleware)


			err := authService.LogoutUserFromAllDevices(ctx, 2)
			if (err != nil) != testScenario.wantErr{
				t.Errorf("RefreshToken() error = %v, wantErr = %v", err, testScenario.wantErr)
			}

			if err != nil && testScenario.err != nil {
				if err.Error() != testScenario.err.Error() {
					t.Errorf("RefreshToken() error = %v, scenarioError = %v", err, testScenario.err)
				}
			}

		})
	}
}