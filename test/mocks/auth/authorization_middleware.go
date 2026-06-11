package mocks

import (
	"net/http"

	"github.com/stretchr/testify/mock"

	userModel "github.com/slodkiadrianek/MINI-BUCKET/internal/user/model"
)

type MockAuthenticationMiddleware struct {
	mock.Mock
}

func (m *MockAuthenticationMiddleware) GenerateRefreshToken() ([]byte, error) {
	args := m.Called()
	return args.Get(0).([]byte), args.Error(1)
}

func (m *MockAuthenticationMiddleware) HashToken(token []byte) string {
	args := m.Called(token)
	return args.Get(0).(string)
}

func (m *MockAuthenticationMiddleware) GenerateAccessToken(user userModel.User) (string, error) {
	args := m.Called(user)
	return args.Get(0).(string), args.Error(1)
}

func (m *MockAuthenticationMiddleware) VerifyToken(r *http.Request) (*http.Request, error) {
	args := m.Called(r)
	return args.Get(0).(*http.Request), args.Error(1)
}

func (m *MockAuthenticationMiddleware) BlacklistUser( r *http.Request) error {
	args := m.Called( r)
	return args.Error(0)
}
