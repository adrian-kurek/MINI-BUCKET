package logger_test

import (
	"encoding/json"
	"log"
	"os"
	"testing"
	"time"

	logger "github.com/slodkiadrianek/MINI-BUCKET/common/logger"
	"gotest.tools/v3/assert"
)

var (
	pathToLogDirectory = "../../tmp/"
	dateFormat         = "2006.01.02"
	timeFormat         = "15:04:05"
)

func removeDirectoryAfterTest() {
	err := os.RemoveAll(pathToLogDirectory)
	if err != nil {
		log.Println(err)
	}
}

func removeFile(t *testing.T, actualDate string) {
	err := os.Remove(pathToLogDirectory + actualDate + ".json")
	if err != nil {
		t.Fatal(err)
	}
}

type logInfo struct {
	Date      string
	TypeOfLog string
	Message   string
	Data      any
}

func TestLoggerInfo(t *testing.T) {
	type args struct {
		name               string
		message            string
		expectedContentLen int
		expectedTypeOfLog  string
	}

	testsCases := []args{
		{
			name:               "Log with message",
			message:            "Test string",
			expectedContentLen: 219,
			expectedTypeOfLog:  "INFO",
		},
	}

	for _, testCase := range testsCases {
		t.Run(testCase.name, func(t *testing.T) {
			loggerSvc := logger.New(pathToLogDirectory, dateFormat, timeFormat)
			loggerSvc.Info(testCase.message, "")
			err := loggerSvc.Close()
			if err != nil {
				panic(err)
			}

			actualDate := time.Now().Format(dateFormat)
			content, _ := os.ReadFile(pathToLogDirectory + actualDate + ".json")

			var logs []logInfo
			err = json.Unmarshal(content, &logs)
			if err != nil {
				t.Fatal(err)
			}

			assert.Equal(t, testCase.expectedContentLen, len(content))
			for i := 1; i < len(logs); i++ {
				assert.Equal(t, testCase.expectedTypeOfLog, logs[i].TypeOfLog)
				assert.Equal(t, testCase.message, logs[i].Message)
			}
		})
	}
	removeDirectoryAfterTest()
}

func TestLoggerWarning(t *testing.T) {
	type args struct {
		name               string
		message            string
		expectedContentLen int
		expectedTypeOfLog  string
	}

	testsCases := []args{
		{
			name:               "Log with message",
			message:            "Test string",
			expectedContentLen: 222,
			expectedTypeOfLog:  "WARNING",
		},
	}

	for _, testCase := range testsCases {
		t.Run(testCase.name, func(t *testing.T) {
			loggerSvc := logger.New(pathToLogDirectory, dateFormat, timeFormat)
			loggerSvc.Warning(testCase.message, "")
			err := loggerSvc.Close()
			if err != nil {
				panic(err)
			}

			actualDate := time.Now().Format(dateFormat)
			content, _ := os.ReadFile(pathToLogDirectory + actualDate + ".json")

			var logs []logInfo
			err = json.Unmarshal(content, &logs)
			if err != nil {
				t.Fatal(err)
			}

			assert.Equal(t, testCase.expectedContentLen, len(content))
			for i := 1; i < len(logs); i++ {
				assert.Equal(t, testCase.expectedTypeOfLog, logs[i].TypeOfLog)
				assert.Equal(t, testCase.message, logs[i].Message)
			}
		})
	}
	removeDirectoryAfterTest()
}

func TestLoggerError(t *testing.T) {
	type args struct {
		name               string
		message            string
		expectedContentLen int
		expectedTypeOfLog  string
	}

	testsCases := []args{
		{
			name:               "Log with message",
			message:            "Test string",
			expectedContentLen: 220,
			expectedTypeOfLog:  "ERROR",
		},
	}

	for _, testCase := range testsCases {
		t.Run(testCase.name, func(t *testing.T) {
			loggerSvc := logger.New(pathToLogDirectory, dateFormat, timeFormat)
			loggerSvc.Error(testCase.message, "")
			err := loggerSvc.Close()
			if err != nil {
				panic(err)
			}

			actualDate := time.Now().Format(dateFormat)
			content, _ := os.ReadFile(pathToLogDirectory + actualDate + ".json")

			var logs []logInfo
			err = json.Unmarshal(content, &logs)
			if err != nil {
				t.Fatal(err)
			}

			assert.Equal(t, testCase.expectedContentLen, len(content))
			for i := 1; i < len(logs); i++ {
				assert.Equal(t, testCase.expectedTypeOfLog, logs[i].TypeOfLog)
				assert.Equal(t, testCase.message, logs[i].Message)
			}
		})
	}
	removeDirectoryAfterTest()
}

func TestLoggerValidate(t *testing.T) {
	type args struct {
		name               string
		message            string
		expectedContentLen int
		expectedTypeOfLog  string
	}
	testsCases := []args{
		{
			name:               "Properly created new file due to day change",
			message:            "Test",
			expectedContentLen: 116,
			expectedTypeOfLog:  "INFO",
		},
	}

	for _, testCase := range testsCases {
		t.Run(testCase.name, func(t *testing.T) {
			actualDate := time.Now().Format(dateFormat)

			loggerSvc := logger.New(pathToLogDirectory, dateFormat, timeFormat)

			removeFile(t, actualDate)

			loggerSvc.StartTime = time.Now().Add(time.Hour * time.Duration(-24)).Format(dateFormat)
			loggerSvc.Validate()
			err := loggerSvc.Close()
			if err != nil {
				panic(err)
			}

			content, _ := os.ReadFile(pathToLogDirectory + actualDate + ".json")

			var logs []logInfo
			err = json.Unmarshal(content, &logs)
			if err != nil {
				t.Fatal(err)
			}

			assert.Equal(t, testCase.expectedContentLen, len(content))
			for i := 1; i < len(logs); i++ {
				assert.Equal(t, testCase.expectedTypeOfLog, logs[i].TypeOfLog)
				assert.Equal(t, testCase.message, logs[i].Message)
			}
		})
	}
	removeDirectoryAfterTest()
}
