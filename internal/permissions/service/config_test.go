package service_test

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

func setupPermissionsServiceDependencies() *logger.Logger {
	return logger.NewLogger("./logs", "2006-01-02", "15:04:05")
}
