package service

import (
	"context"
	"errors"
	"testing"
	"time"

	commonInterfaces "github.com/slodkiadrianek/MINI-BUCKET/common/interfaces"
	authModel "github.com/slodkiadrianek/MINI-BUCKET/internal/auth/model"
	"github.com/slodkiadrianek/MINI-BUCKET/test/mocks"
	authMocks "github.com/slodkiadrianek/MINI-BUCKET/test/mocks/auth"
	"github.com/stretchr/testify/mock"
)

func TestRefreshToken(t *testing.T) {
	type args struct {
		title        string
		refreshToken []byte
		setupMock    func() (authRepository, commonInterfaces.UserRepository, commonInterfaces.AuthorizationMiddleware)
		wantErr      bool
		err          error
	}
	testsScenarios := []args{
		{
			title:        "with proper data",
			refreshToken: []byte("123456789"),
			setupMock: func() (authRepository, commonInterfaces.UserRepository, commonInterfaces.AuthorizationMiddleware) {
				mAuthRepository := new(authMocks.MockAuthRepository)
				mAuthorizationMiddleware := new(authMocks.MockAuthorizationMiddleware)
				mUserRepository := new(mocks.MockUserRepository)
				mAuthorizationMiddleware.On("HashToken", mock.Anything).Return("abcdef")
				mAuthRepository.On("GetRefreshTokenByTokenHash", mock.Anything, mock.Anything).Return(authModel.TokenWithUserEmailToRefreshToken{
					ID:        1,
					ExpiresAt: time.Now().Add(10 * time.Minute),
				}, nil)
				mAuthRepository.On("UpdateLastTimeUsedToken", mock.Anything, mock.Anything).Return(nil)
				mAuthorizationMiddleware.On("GenerateAccessToken", mock.Anything).Return("123456", nil)
				return mAuthRepository, mUserRepository, mAuthorizationMiddleware
			},
			wantErr: false,
			err:     nil,
		},
		{
			title:        "GetRefreshTokenByTokenHash failed",
			refreshToken: []byte("123456789"),
			setupMock: func() (authRepository, commonInterfaces.UserRepository, commonInterfaces.AuthorizationMiddleware) {
				mAuthRepository := new(authMocks.MockAuthRepository)
				mAuthorizationMiddleware := new(authMocks.MockAuthorizationMiddleware)
				mUserRepository := new(mocks.MockUserRepository)
				mAuthorizationMiddleware.On("HashToken", mock.Anything).Return("abcdef")
				mAuthRepository.On("GetRefreshTokenByTokenHash", mock.Anything, mock.Anything).Return(authModel.TokenWithUserEmailToRefreshToken{}, errors.New("failed to get token from DB"))
				return mAuthRepository, mUserRepository, mAuthorizationMiddleware
			},
			wantErr: true,
			err:     errors.New("failed to get token from DB"),
		},
		{
			title:        "token not found",
			refreshToken: []byte("123456789"),
			setupMock: func() (authRepository, commonInterfaces.UserRepository, commonInterfaces.AuthorizationMiddleware) {
				mAuthRepository := new(authMocks.MockAuthRepository)
				mAuthorizationMiddleware := new(authMocks.MockAuthorizationMiddleware)
				mUserRepository := new(mocks.MockUserRepository)
				mAuthorizationMiddleware.On("HashToken", mock.Anything).Return("abcdef")
				mAuthRepository.On("GetRefreshTokenByTokenHash", mock.Anything, mock.Anything).Return(authModel.TokenWithUserEmailToRefreshToken{
					ID: 0,
				}, nil)
				return mAuthRepository, mUserRepository, mAuthorizationMiddleware
			},
			wantErr: true,
			err:     errors.New("api error: token not found"),
		},
		{
			title:        "refresh token expired",
			refreshToken: []byte("123456789"),
			setupMock: func() (authRepository, commonInterfaces.UserRepository, commonInterfaces.AuthorizationMiddleware) {
				mAuthRepository := new(authMocks.MockAuthRepository)
				mAuthorizationMiddleware := new(authMocks.MockAuthorizationMiddleware)
				mUserRepository := new(mocks.MockUserRepository)
				mAuthorizationMiddleware.On("HashToken", mock.Anything).Return("abcdef")
				mAuthRepository.On("GetRefreshTokenByTokenHash", mock.Anything, mock.Anything).Return(authModel.TokenWithUserEmailToRefreshToken{
					ID:        1,
					ExpiresAt: time.Now().Add(-2 * time.Minute),
				}, nil)
				return mAuthRepository, mUserRepository, mAuthorizationMiddleware
			},
			wantErr: true,
			err:     errors.New("api error: refresh token expired"),
		},
		{
			title:        "UpdateLastTimeUsedToken failed",
			refreshToken: []byte("123456789"),
			setupMock: func() (authRepository, commonInterfaces.UserRepository, commonInterfaces.AuthorizationMiddleware) {
				mAuthRepository := new(authMocks.MockAuthRepository)
				mAuthorizationMiddleware := new(authMocks.MockAuthorizationMiddleware)
				mUserRepository := new(mocks.MockUserRepository)
				mAuthorizationMiddleware.On("HashToken", mock.Anything).Return("abcdef")
				mAuthRepository.On("GetRefreshTokenByTokenHash", mock.Anything, mock.Anything).Return(authModel.TokenWithUserEmailToRefreshToken{
					ID:        1,
					ExpiresAt: time.Now().Add(10 * time.Minute),
				}, nil)
				mAuthRepository.On("UpdateLastTimeUsedToken", mock.Anything, mock.Anything).Return(errors.New("failed to update last time used token"))
				// mAuthorizationMiddleware.On("GenerateAccessToken", mock.Anything).Return("123456", nil)
				return mAuthRepository, mUserRepository, mAuthorizationMiddleware
			},
			wantErr: true,
			err:     errors.New("failed to update last time used token"),
		},
		{
			title:        "GenerateAccessToken failed",
			refreshToken: []byte("123456789"),
			setupMock: func() (authRepository, commonInterfaces.UserRepository, commonInterfaces.AuthorizationMiddleware) {
				mAuthRepository := new(authMocks.MockAuthRepository)
				mAuthorizationMiddleware := new(authMocks.MockAuthorizationMiddleware)
				mUserRepository := new(mocks.MockUserRepository)
				mAuthorizationMiddleware.On("HashToken", mock.Anything).Return("abcdef")
				mAuthRepository.On("GetRefreshTokenByTokenHash", mock.Anything, mock.Anything).Return(authModel.TokenWithUserEmailToRefreshToken{
					ID:        1,
					ExpiresAt: time.Now().Add(10 * time.Minute),
				}, nil)
				mAuthRepository.On("UpdateLastTimeUsedToken", mock.Anything, mock.Anything).Return(nil)
				mAuthorizationMiddleware.On("GenerateAccessToken", mock.Anything).Return("", errors.New("failed to generate new access token"))
				return mAuthRepository, mUserRepository, mAuthorizationMiddleware
			},
			wantErr: true,
			err:     errors.New("failed to generate new access token"),
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

			_, err := authService.RefreshToken(ctx, testScenario.refreshToken)
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