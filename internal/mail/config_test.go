package mail_test

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

func setupAuthServiceDependencies() *logger.Logger {
	loggerService := logger.New("./logs", "2006-01-02", "15:04:05")
	return loggerService
}
