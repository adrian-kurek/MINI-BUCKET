package service


import (
	"context"
	"errors"
	"testing"
	"time"
	commonInterfaces "github.com/slodkiadrianek/MINI-BUCKET/internal/common/interfaces"
	"github.com/slodkiadrianek/MINI-BUCKET/test/mocks"
	authMocks "github.com/slodkiadrianek/MINI-BUCKET/test/mocks/auth"
	"github.com/stretchr/testify/mock"
)
func TestLogoutUser(t *testing.T) {
	type args struct {
		title     string
		setupMock func() (authRepository, commonInterfaces.UserRepository, commonInterfaces.AuthorizationMiddleware)
		wantErr   bool
		err       error
	}

	testsScenarios := []args{
		{
			title: "with proper data",

			setupMock: func() (authRepository, commonInterfaces.UserRepository, commonInterfaces.AuthorizationMiddleware) {
				mAuthRepository := new(authMocks.MockAuthRepository)
				mAuthorizationMiddleware := new(authMocks.MockAuthorizationMiddleware)
				mUserRepository := new(mocks.MockUserRepository)

				mAuthorizationMiddleware.On("HashToken", mock.Anything).Return("12345")
				mAuthRepository.On("RemoveTokenFromDB", mock.Anything, mock.Anything).Return(nil)
				return mAuthRepository, mUserRepository, mAuthorizationMiddleware
			},
			wantErr: false,
			err:     nil,
		},
		{
			title: "RemoveTokenFromDB failed",

			setupMock: func() (authRepository, commonInterfaces.UserRepository, commonInterfaces.AuthorizationMiddleware) {
				mAuthRepository := new(authMocks.MockAuthRepository)
				mAuthorizationMiddleware := new(authMocks.MockAuthorizationMiddleware)
				mUserRepository := new(mocks.MockUserRepository)

				mAuthorizationMiddleware.On("HashToken", mock.Anything).Return("12345")
				mAuthRepository.On("RemoveTokenFromDB", mock.Anything, mock.Anything).Return(errors.New("failed to remove token from DB"))
				return mAuthRepository, mUserRepository, mAuthorizationMiddleware
			},
			wantErr: true,
			err:     errors.New("failed to remove token from DB"),
		},
	}

	for _, testScenario := range testsScenarios {
		t.Run(testScenario.title, func(t *testing.T) {
			ctx, cancel := context.WithTimeout(context.Background(), 2*time.Second)
			defer cancel()

			authRepository, userRepository, authorizationMiddleware := testScenario.setupMock()
			loggerService := setupAuthServiceDependencies()
			emailService := new(authMocks.MockEmailService)
			authService := NewAuthService(loggerService, userRepository, authRepository, authorizationMiddleware, emailService)

			err := authService.LogoutUser(ctx, []byte("123456"))
			if (err != nil) != testScenario.wantErr {
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

func TestLogoutUserFromAllDevices(t *testing.T) {
	type args struct {
		title     string
		setupMock func() (authRepository, commonInterfaces.UserRepository, commonInterfaces.AuthorizationMiddleware)
		wantErr   bool
		err       error
	}

	testsScenarios := []args{
		{
			title: "with proper data",
			setupMock: func() (authRepository, commonInterfaces.UserRepository, commonInterfaces.AuthorizationMiddleware) {
				mAuthRepository := new(authMocks.MockAuthRepository)
				mAuthorizationMiddleware := new(authMocks.MockAuthorizationMiddleware)
				mUserRepository := new(mocks.MockUserRepository)

				mAuthRepository.On("RemoveTokensFromDBByUserID", mock.Anything, mock.Anything).Return(nil)
				return mAuthRepository, mUserRepository, mAuthorizationMiddleware
			},
			wantErr: false,
			err:     nil,
		},
		{
			title: "RemoveTokenFromDB failed",

			setupMock: func() (authRepository, commonInterfaces.UserRepository, commonInterfaces.AuthorizationMiddleware) {
				mAuthRepository := new(authMocks.MockAuthRepository)
				mAuthorizationMiddleware := new(authMocks.MockAuthorizationMiddleware)
				mUserRepository := new(mocks.MockUserRepository)

				mAuthRepository.On("RemoveTokensFromDBByUserID", mock.Anything, mock.Anything).Return(errors.New("failed to remove token from DB"))
				return mAuthRepository, mUserRepository, mAuthorizationMiddleware
			},
			wantErr: true,
			err:     errors.New("failed to remove token from DB"),
		},
	}

	for _, testScenario := range testsScenarios {
		t.Run(testScenario.title, func(t *testing.T) {
			ctx, cancel := context.WithTimeout(context.Background(), 2*time.Second)
			defer cancel()

			authRepository, userRepository, authorizationMiddleware := testScenario.setupMock()
			loggerService := setupAuthServiceDependencies()
			emailService := new(authMocks.MockEmailService)
			authService := NewAuthService(loggerService, userRepository, authRepository, authorizationMiddleware, emailService)

			err := authService.LogoutUserFromAllDevices(ctx, 2)
			if (err != nil) != testScenario.wantErr {
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