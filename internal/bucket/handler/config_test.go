package handler_test

import (
	"os"
	"testing"

	"github.com/slodkiadrianek/MINI-BUCKET/common/log"
)

func TestMain(m *testing.M) {
	code := m.Run()
	os.RemoveAll("logs")
	os.Exit(code)
}

func setupBucketHandlerDependencies() *log.Logger {
	return log.NewLogger("./logs", "2006-01-02", "15:04:05")
}
