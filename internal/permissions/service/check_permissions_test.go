package service

import (
	"context"
	"errors"
	"testing"
	"time"

	permissionMocks "github.com/slodkiadrianek/MINI-BUCKET/test/mocks/permissions"
	"github.com/stretchr/testify/mock"
)

func TestCheckPermissions(t *testing.T) {
	type args struct {
		title     string
		setupMock func() permissionRepository
		wantErr   bool
		err       error
	}

	testScenarios := []args{
		{
			title: "with proper data",
			setupMock: func() permissionRepository {
				mPermissionRepository := new(permissionMocks.MockPermissionRepository)
				mPermissionRepository.On("GetPermissionValByUserID", mock.Anything, mock.Anything, mock.Anything).Return(7, nil)
				return mPermissionRepository
			},
			wantErr: false,
			err:     nil,
		},
		{
			title: "user is not allowed to perform an action",
			setupMock: func() permissionRepository {
				mPermissionRepository := new(permissionMocks.MockPermissionRepository)
				mPermissionRepository.On("GetPermissionValByUserID", mock.Anything, mock.Anything, mock.Anything).Return(2, nil)
				return mPermissionRepository
			},
			wantErr: true,
			err:     errors.New("api error: you are not allowed to do this action"),
		},
		{
			title: "GetPermissionValByUserID failed",
			setupMock: func() permissionRepository {
				mPermissionRepository := new(permissionMocks.MockPermissionRepository)
				mPermissionRepository.On("GetPermissionValByUserID", mock.Anything, mock.Anything, mock.Anything).Return(0, errors.New("failed to get data from db"))
				return mPermissionRepository
			},
			wantErr: true,
			err:     errors.New("failed to get data from db"),
		},
	}

	for _, testScenario := range testScenarios {
		t.Run(testScenario.title, func(t *testing.T) {
			ctx, cancel := context.WithTimeout(context.Background(), 2*time.Second)
			defer cancel()

			permissionRepository := testScenario.setupMock()
			loggerService := setupPermissionsServiceDependencies()
			permissionService := NewPermissionRepository(permissionRepository, loggerService)

			err := permissionService.checkPermissions(ctx, 1, 1)
			if (err != nil) != testScenario.wantErr {
				t.Errorf("CheckPermissions() error = %v, wantErr = %v", err, testScenario.wantErr)
			}

			if err != nil && testScenario.err != nil {
				if err.Error() != testScenario.err.Error() {
					t.Errorf("CheckPermissions() error = %v, scenarioError = %v", err, testScenario.err)
				}
			}
		})
	}
}
