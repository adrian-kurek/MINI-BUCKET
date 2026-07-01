package repository_test

import (
	"log"
	"os"
	"testing"

	"github.com/slodkiadrianek/MINI-BUCKET/common/logger"
)

func TestMain(m *testing.M) {
	code := m.Run()
	err := os.RemoveAll("logs")
	if err != nil {
		log.Println(err.Error())
	}
	os.Exit(code)
}

func setupVersionRepositoryDependencies() *logger.Logger {
	return logger.New("./logs", "2006-01-02", "15:04:05")
}
