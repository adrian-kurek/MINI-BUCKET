package service_test

import (
	"context"
	"errors"
	"testing"
	"time"

	authService "github.com/slodkiadrianek/MINI-BUCKET/internal/auth/service"
	"github.com/slodkiadrianek/MINI-BUCKET/test/mocks"
	authMocks "github.com/slodkiadrianek/MINI-BUCKET/test/mocks/auth"
	"github.com/stretchr/testify/mock"
)

func TestActivateAccount(t *testing.T) {
	type args struct {
		title     string
		setupMock func() authService.AuthRepository
		wantErr   bool
		err       error
	}

	testsScenarios := []args{
		{
			title: "with proper data",
			setupMock: func() authService.AuthRepository {
				mAuthRepository := new(authMocks.MockAuthRepository)
				mAuthRepository.On("ActivateAccount", mock.Anything, mock.Anything).Return(nil)
				return mAuthRepository
			},
			wantErr: false,
			err:     nil,
		},
		{
			title: "ActivateAccount failed",
			setupMock: func() authService.AuthRepository {
				mAuthRepository := new(authMocks.MockAuthRepository)
				mAuthRepository.On("ActivateAccount", mock.Anything, mock.Anything).
					Return(errors.New("failed to activate account"))
				return mAuthRepository
			},
			wantErr: true,
			err:     errors.New("failed to activate account"),
		},
	}

	for _, testScenario := range testsScenarios {
		t.Run(testScenario.title, func(t *testing.T) {
			ctx, cancel := context.WithTimeout(context.Background(), 2*time.Second)
			defer cancel()

			authRepository := testScenario.setupMock()
			loggerService := setupAuthServiceDependencies()
			emailService := new(authMocks.MockEmailService)
			userRepository := new(mocks.MockUserRepository)
			authorizationMiddleware := new(authMocks.MockAuthenticationMiddleware)
			authService := authService.NewAuthService(
				loggerService,
				userRepository,
				authRepository,
				authorizationMiddleware,
				emailService,
			)

			err := authService.ActivateAccount(ctx, 1)
			if (err != nil) != testScenario.wantErr {
				t.Errorf("ActivateAccount() error = %v, wantErr = %v", err, testScenario.wantErr)
			}

			if err != nil && testScenario.err != nil {
				if err.Error() != testScenario.err.Error() {
					t.Errorf("ActivateAccount() error = %v, scenarioError = %v", err, testScenario.err)
				}
			}
		})
	}
}
