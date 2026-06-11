package service

import (
	"context"
	"errors"
	"testing"
	"time"

	commonInterfaces "github.com/slodkiadrianek/MINI-BUCKET/common/interfaces"
	authDto "github.com/slodkiadrianek/MINI-BUCKET/internal/auth/DTO"
	userModel "github.com/slodkiadrianek/MINI-BUCKET/internal/user/model"
	"github.com/slodkiadrianek/MINI-BUCKET/test/mocks"
	authMocks "github.com/slodkiadrianek/MINI-BUCKET/test/mocks/auth"
	"github.com/stretchr/testify/mock"
)


func TestLogin(t *testing.T) {
	type args struct {
		title     string
		user      authDto.LoginUser
		setupMock func() (authRepository, userRepository, commonInterfaces.AuthenticationMiddleware, emailService)
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
			setupMock: func() (authRepository, userRepository, commonInterfaces.AuthenticationMiddleware, emailService) {
				mAuthRepository := new(authMocks.MockAuthRepository)
				mUserRepository := new(mocks.MockUserRepository)
				mAuthenticationMiddleware := new(authMocks.MockAuthenticationMiddleware)
				mEmailService := new(authMocks.MockEmailService)
				mEmailService.On("SendEmail", mock.Anything, mock.Anything, mock.Anything).Return(nil)
				mAuthRepository.On("InsertRefreshToken", mock.Anything, mock.Anything, mock.Anything, mock.Anything, mock.Anything).Return(nil)
				mUserRepository.On("FindByEmail", mock.Anything, mock.Anything).Return(userModel.User{
					ID:            1,
					EmailVerified: true,
					Password:      "$2a$12$uqfZc1qMbaeN2HKUQhY6SOimGPw6j6Vam6njGSJfbz.bghZGAwkOK",
				}, nil)
				mAuthenticationMiddleware.On("GenerateAccessToken", mock.Anything).Return("123245", nil)
				mAuthenticationMiddleware.On("GenerateRefreshToken").Return([]byte("2324242"), nil)
				mAuthenticationMiddleware.On("HashToken", mock.Anything).Return("12345")

				return mAuthRepository, mUserRepository, mAuthenticationMiddleware, mEmailService
			},
			wantErr: false,
			err:     nil,
		},
		{
			title: "FindByEmail failed",
			user: authDto.LoginUser{
				Email:    "joedoe@gmail.com",
				Password: "zasfsafds@#!sdwe32",
			},
			setupMock: func() (authRepository, userRepository, commonInterfaces.AuthenticationMiddleware, emailService) {
				mAuthRepository := new(authMocks.MockAuthRepository)
				mUserRepository := new(mocks.MockUserRepository)
				mEmailService := new(authMocks.MockEmailService)
				mEmailService.On("SendEmail", mock.Anything, mock.Anything, mock.Anything).Return(nil)
				mAuthenticationMiddleware := new(authMocks.MockAuthenticationMiddleware)
				mUserRepository.On("FindByEmail", mock.Anything, mock.Anything).Return(userModel.User{}, errors.New("failed to get user from DB"))
				return mAuthRepository, mUserRepository, mAuthenticationMiddleware, mEmailService
			},
			wantErr: true,
			err:     errors.New("failed to get user from DB"),
		},
		{
			title: "user with provided email not found",
			user: authDto.LoginUser{
				Email:    "joedoe@gmail.com",
				Password: "zasfsafds@#!sdwe32",
			},
			setupMock: func() (authRepository, userRepository, commonInterfaces.AuthenticationMiddleware, emailService) {
				mAuthRepository := new(authMocks.MockAuthRepository)
				mUserRepository := new(mocks.MockUserRepository)
				mEmailService := new(authMocks.MockEmailService)
				mEmailService.On("SendEmail", mock.Anything, mock.Anything, mock.Anything).Return(nil)
				mAuthenticationMiddleware := new(authMocks.MockAuthenticationMiddleware)
				mUserRepository.On("FindByEmail", mock.Anything, mock.Anything).Return(userModel.User{
					ID: 0,
				}, nil)

				return mAuthRepository, mUserRepository, mAuthenticationMiddleware, mEmailService
			},
			wantErr: true,
			err:     errors.New("api error: user with provided email not found"),
		},
		{
			title: "user with provided email is not verified",
			user: authDto.LoginUser{
				Email:    "joedoe@gmail.com",
				Password: "zasfsafds@#!sdwe32",
			},
			setupMock: func() (authRepository, userRepository, commonInterfaces.AuthenticationMiddleware, emailService) {
				mAuthRepository := new(authMocks.MockAuthRepository)
				mUserRepository := new(mocks.MockUserRepository)
				mEmailService := new(authMocks.MockEmailService)
				mEmailService.On("SendEmail", mock.Anything, mock.Anything, mock.Anything).Return(nil)
				mAuthenticationMiddleware := new(authMocks.MockAuthenticationMiddleware)
				mAuthenticationMiddleware.On("GenerateAccessToken", mock.Anything).Return("123245", nil)
				mUserRepository.On("FindByEmail", mock.Anything, mock.Anything).Return(userModel.User{
					EmailVerified: false,
					ID:            1,
				}, nil)

				return mAuthRepository, mUserRepository, mAuthenticationMiddleware,mEmailService
			},
			wantErr: true,
			err:     errors.New("api error: user with provided email is not verified, we sent to you mail with activation link"),
		},
		{
			title: "failed to send email with activation link",
			user: authDto.LoginUser{
				Email:    "joedoe@gmail.com",
				Password: "zasfsafds@#!sdwe32",
			},
			setupMock: func() (authRepository, userRepository, commonInterfaces.AuthenticationMiddleware, emailService) {
				mAuthRepository := new(authMocks.MockAuthRepository)
				mUserRepository := new(mocks.MockUserRepository)
				mAuthenticationMiddleware := new(authMocks.MockAuthenticationMiddleware)
				mEmailService := new(authMocks.MockEmailService)
				mEmailService.On("SendEmail", mock.Anything, mock.Anything, mock.Anything).Return(errors.New("failed to send email with activation link"))
				mUserRepository.On("FindByEmail", mock.Anything, mock.Anything).Return(userModel.User{
					ID:            1,
					EmailVerified: false,
					Password:      "$2a$12$uqfZc1qMbaeN2HKUQhY6SOimGPw6j6Vam6njGSJfbz.bghZGAwkOK",
				}, nil)
				mAuthenticationMiddleware.On("GenerateAccessToken", mock.Anything).Return("123245", nil)

				return mAuthRepository, mUserRepository, mAuthenticationMiddleware, mEmailService
			},
			wantErr: true,
			err:     errors.New("failed to send email with activation link"),
		},
		{
			title: "failed to generateAccessToken for activation link",
			user: authDto.LoginUser{
				Email:    "joedoe@gmail.com",
				Password: "zasfsafds@#!sdwe32",
			},
			setupMock: func() (authRepository, userRepository, commonInterfaces.AuthenticationMiddleware, emailService) {
				mAuthRepository := new(authMocks.MockAuthRepository)
				mUserRepository := new(mocks.MockUserRepository)
				mAuthenticationMiddleware := new(authMocks.MockAuthenticationMiddleware)
				mEmailService := new(authMocks.MockEmailService)
				mUserRepository.On("FindByEmail", mock.Anything, mock.Anything).Return(userModel.User{
					ID:            1,
					EmailVerified: false,
					Password:      "$2a$12$uqfZc1qMbaeN2HKUQhY6SOimGPw6j6Vam6njGSJfbz.bghZGAwkOK",
				}, nil)
				mAuthenticationMiddleware.On("GenerateAccessToken", mock.Anything).Return("123245", errors.New("failed to generate new access token"))

				return mAuthRepository, mUserRepository, mAuthenticationMiddleware, mEmailService
			},
			wantErr: true,
			err:     errors.New("failed to generate new access token"),
		},
		{
			title: "provided incorrect password",
			user: authDto.LoginUser{
				Email:    "joedoe@gmail.com",
				Password: "zasfsafds@#!sdwe37",
			},
			setupMock: func() (authRepository, userRepository, commonInterfaces.AuthenticationMiddleware, emailService) {
				mAuthRepository := new(authMocks.MockAuthRepository)
				mUserRepository := new(mocks.MockUserRepository)
				mAuthenticationMiddleware := new(authMocks.MockAuthenticationMiddleware)
				mEmailService := new(authMocks.MockEmailService)
				mEmailService.On("SendEmail", mock.Anything, mock.Anything, mock.Anything).Return(nil)
				mUserRepository.On("FindByEmail", mock.Anything, mock.Anything).Return(userModel.User{
					ID:            1,
					EmailVerified: true,
					Password:      "$2a$12$uqfZc1qMbaeN2HKUQhY6SOimGPw6j6Vam6njGSJfbz.bghZGAwkOK",
				}, nil)

				return mAuthRepository, mUserRepository, mAuthenticationMiddleware, mEmailService
			},
			wantErr: true,
			err:     errors.New("api error: provided incorrect password"),
		},
		{
			title: "GenerateAccessToken failed",
			user: authDto.LoginUser{
				Email:    "joedoe@gmail.com",
				Password: "zasfsafds@#!sdwe32",
			},
			setupMock: func() (authRepository, userRepository, commonInterfaces.AuthenticationMiddleware, emailService) {
				mAuthRepository := new(authMocks.MockAuthRepository)
				mUserRepository := new(mocks.MockUserRepository)
				mAuthenticationMiddleware := new(authMocks.MockAuthenticationMiddleware)
				mEmailService := new(authMocks.MockEmailService)
				mEmailService.On("SendEmail", mock.Anything, mock.Anything, mock.Anything).Return(nil)
				mUserRepository.On("FindByEmail", mock.Anything, mock.Anything).Return(userModel.User{
					ID:            1,
					EmailVerified: true,
					Password:      "$2a$12$uqfZc1qMbaeN2HKUQhY6SOimGPw6j6Vam6njGSJfbz.bghZGAwkOK",
				}, nil)
				mAuthenticationMiddleware.On("GenerateAccessToken", mock.Anything).Return("", errors.New("failed to generate new access token"))

				return mAuthRepository, mUserRepository, mAuthenticationMiddleware, mEmailService
			},
			wantErr: true,
			err:     errors.New("failed to generate new access token"),
		},
		{
			title: "GenerateRefreshToken failed",
			user: authDto.LoginUser{
				Email:    "joedoe@gmail.com",
				Password: "zasfsafds@#!sdwe32",
			},
			setupMock: func() (authRepository, userRepository, commonInterfaces.AuthenticationMiddleware, emailService) {
				mAuthRepository := new(authMocks.MockAuthRepository)
				mUserRepository := new(mocks.MockUserRepository)
				mAuthenticationMiddleware := new(authMocks.MockAuthenticationMiddleware)
				mEmailService := new(authMocks.MockEmailService)
				mEmailService.On("SendEmail", mock.Anything, mock.Anything, mock.Anything).Return(nil)
				mUserRepository.On("FindByEmail", mock.Anything, mock.Anything).Return(userModel.User{
					ID:            1,
					EmailVerified: true,
					Password:      "$2a$12$uqfZc1qMbaeN2HKUQhY6SOimGPw6j6Vam6njGSJfbz.bghZGAwkOK",
				}, nil)
				mAuthenticationMiddleware.On("GenerateAccessToken", mock.Anything).Return("123245", nil)
				mAuthenticationMiddleware.On("GenerateRefreshToken").Return([]byte("2324242"), errors.New("failed to generate new refresh token"))

				return mAuthRepository, mUserRepository, mAuthenticationMiddleware, mEmailService
			},
			wantErr: true,
			err:     errors.New("failed to generate new refresh token"),
		},
		{
			title: "InsertRefreshToken failed",
			user: authDto.LoginUser{
				Email:    "joedoe@gmail.com",
				Password: "zasfsafds@#!sdwe32",
			},
			setupMock: func() (authRepository, userRepository, commonInterfaces.AuthenticationMiddleware, emailService) {
				mAuthRepository := new(authMocks.MockAuthRepository)
				mUserRepository := new(mocks.MockUserRepository)
				mEmailService := new(authMocks.MockEmailService)
				mEmailService.On("SendEmail", mock.Anything, mock.Anything, mock.Anything).Return(nil)
				mAuthenticationMiddleware := new(authMocks.MockAuthenticationMiddleware)
				mAuthRepository.On("InsertRefreshToken", mock.Anything, mock.Anything, mock.Anything, mock.Anything, mock.Anything).Return(errors.New("failed to insert refresh token to DB"))
				mUserRepository.On("FindByEmail", mock.Anything, mock.Anything).Return(userModel.User{
					ID:            1,
					EmailVerified: true,
					Password:      "$2a$12$uqfZc1qMbaeN2HKUQhY6SOimGPw6j6Vam6njGSJfbz.bghZGAwkOK",
				}, nil)
				mAuthenticationMiddleware.On("GenerateAccessToken", mock.Anything).Return("123245", nil)
				mAuthenticationMiddleware.On("GenerateRefreshToken").Return([]byte("2324242"), nil)
				mAuthenticationMiddleware.On("HashToken", mock.Anything).Return("12345")

				return mAuthRepository, mUserRepository, mAuthenticationMiddleware, mEmailService
			},
			wantErr: true,
			err:     errors.New("failed to insert refresh token to DB"),
		},
	}

	for _, testScenario := range testsScenarios {
		t.Run(testScenario.title, func(t *testing.T) {
			ctx, cancel := context.WithTimeout(context.Background(), 2*time.Second)
			defer cancel()

			authRepository, userRepository, authorizationMiddleware , emailService := testScenario.setupMock()
			loggerService := setupAuthServiceDependencies()
			authService := NewAuthService(loggerService, userRepository, authRepository, authorizationMiddleware, emailService)

			ipAddress := "127.0.0.1:2137"
			deviceInfo := "Apple computer"

			_, _, err := authService.Login(ctx, testScenario.user, ipAddress, deviceInfo)
			if (err != nil) != testScenario.wantErr {
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