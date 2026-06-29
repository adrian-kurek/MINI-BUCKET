package repository_test

import (
	"os"
	"testing"

	"github.com/slodkiadrianek/MINI-BUCKET/common/logger"
)

func TestMain(m *testing.M) {
	code := m.Run()
	os.RemoveAll("logs")
	os.Exit(code)
}

func setupUserRepositoryDependencies() *logger.Logger {
	loggerService := logger.NewLogger("./logs", "2006-01-02", "15:04:05")
	return loggerService
}
