package repository

import (
	"fmt"

	"github.com/slodkiadrianek/MINI-BUCKET/internal/log"
)

func setupAuthRepositoryDependencies() *log.Logger {
	loggerService := log.NewLogger("./logs", "2006-01-02", "15:04:05")
	defer func() {
		if closeErr := loggerService.Close(); closeErr != nil {
			fmt.Printf("failed to properly close file with logs:%s", closeErr.Error())
		}
	}()

	return loggerService
}
