package mail_test

import (
	"os"
	"testing"

	config "github.com/slodkiadrianek/MINI-BUCKET/configs"
	emailService "github.com/slodkiadrianek/MINI-BUCKET/internal/mail"
	mocks "github.com/slodkiadrianek/MINI-BUCKET/test/mocks/auth"
	"github.com/stretchr/testify/mock"
)

func TestSendEmail(t *testing.T) {
	type args struct {
		title   string
		to      string
		wantErr bool
	}

	testsScenarios := []args{
		{
			title:   "with proper data",
			to:      "test@gmail.com",
			wantErr: false,
		},
		{
			title:   "with empty email",
			to:      "",
			wantErr: true,
		},
	}

	for _, testScenario := range testsScenarios {
		t.Run(testScenario.title, func(t *testing.T) {
			mEmailService := new(mocks.MockEmailService)
			mEmailService.On("SendEmail", mock.Anything, mock.Anything, mock.Anything).Return(nil)

			err := config.SetupEnvVariables("../../.env")
			if err != nil {
				panic(err)
			}
			loggerService := setupAuthServiceDependencies()
			hostEmail := os.Getenv("HOST_EMAIL")
			emailPassword := os.Getenv("PASSWORD_EMAIL")
			svc := emailService.New(hostEmail, emailPassword, loggerService)
			err = svc.SendEmail(testScenario.to, "subject", "body")

			if (err != nil) != testScenario.wantErr {
				t.Errorf("SendEmail() error = %v, wantErr %v", err, testScenario.wantErr)
			}
		})
	}
}
