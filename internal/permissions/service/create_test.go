package service_test

import (
	"context"
	"errors"
	"testing"
	"time"

	permissionService "github.com/slodkiadrianek/MINI-BUCKET/internal/permissions/service"
	permissionMocks "github.com/slodkiadrianek/MINI-BUCKET/test/mocks/permissions"
	"github.com/stretchr/testify/mock"
)

func TestCreate(t *testing.T) {
	type args struct {
		title     string
		setupMock func() permissionService.PermissionRepository
		wantErr   bool
		err       error
	}

	testScenarios := []args{
		{
			title: "with proper data",
			setupMock: func() permissionService.PermissionRepository {
				mPermissionRepository := new(permissionMocks.MockPermissionRepository)
				mPermissionRepository.On("GetPermissionValByUserID", mock.Anything, mock.Anything, mock.Anything).
					Return(7, nil)
				mPermissionRepository.On("Create", mock.Anything, mock.Anything, mock.Anything, mock.Anything).
					Return(7, nil)
				return mPermissionRepository
			},
			wantErr: false,
			err:     nil,
		},
		{
			title: "user is not allowed to perform an action",
			setupMock: func() permissionService.PermissionRepository {
				mPermissionRepository := new(permissionMocks.MockPermissionRepository)
				mPermissionRepository.On("GetPermissionValByUserID", mock.Anything, mock.Anything, mock.Anything).
					Return(2, nil)
				mPermissionRepository.On("Create", mock.Anything, mock.Anything, mock.Anything, mock.Anything).
					Return(7, nil)
				return mPermissionRepository
			},
			wantErr: true,
			err:     errors.New("api error: you are not allowed to do this action"),
		},

		{
			title: "failed to create new permission",
			setupMock: func() permissionService.PermissionRepository {
				mPermissionRepository := new(permissionMocks.MockPermissionRepository)
				mPermissionRepository.On("GetPermissionValByUserID", mock.Anything, mock.Anything, mock.Anything).
					Return(7, nil)
				mPermissionRepository.On("Create", mock.Anything, mock.Anything, mock.Anything, mock.Anything).
					Return(7, errors.New("failed to create new permission"))
				return mPermissionRepository
			},
			wantErr: true,
			err:     errors.New("failed to create new permission"),
		},
	}

	for _, testScenario := range testScenarios {
		t.Run(testScenario.title, func(t *testing.T) {
			ctx, cancel := context.WithTimeout(context.Background(), 2*time.Second)
			defer cancel()

			permissionRepository := testScenario.setupMock()
			loggerService := setupPermissionsServiceDependencies()
			permissionService := permissionService.NewPermissionRepository(permissionRepository, loggerService)

			err := permissionService.Create(ctx, 1, 1, 1, 7)
			if (err != nil) != testScenario.wantErr {
				t.Errorf("Create() error = %v, wantErr = %v", err, testScenario.wantErr)
			}

			if err != nil && testScenario.err != nil {
				if err.Error() != testScenario.err.Error() {
					t.Errorf("Create() error = %v, scenarioError = %v", err, testScenario.err)
				}
			}
		})
	}
}
