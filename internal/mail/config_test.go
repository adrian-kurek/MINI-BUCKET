package mail

import (
	"fmt"
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
	loggerService := logger.NewLogger("./logs", "2006-01-02", "15:04:05")
	defer func() {
		if closeErr := loggerService.Close(); closeErr != nil {
			fmt.Errorf("failed to properly close file with logs:%s", closeErr.Error())
		}
	}()
	return loggerService
}
