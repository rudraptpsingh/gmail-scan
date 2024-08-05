package services

import (
	"testing"

	"github.com/rudraptpsingh/gmail-scan/src/configs"
	"github.com/rudraptpsingh/gmail-scan/src/logger"
	"github.com/spf13/viper"
)

func init() {
	// Initialize Viper across the application
	configs.InitializeViper()

	// Initialize Logger across the application
	logger.InitializeZapCustomLogger()

	// Run app with GMail OAuth.
	InitGmailOAuthAndRunApp(viper.GetString("port"))
}

func TestSendMail(t *testing.T) {
	t.Log("Testing sending mail")
	var msg message
	msg.to = "rudra.ptp.singh@gmail.com"
	msg.subject = "Test mail from RP"
	msg.body = "Test Body from RP"
	rwGmail := <-OAuthch
	t.Log("User authenticated. Sending mail now")
	if err := rwGmail.SendMail(msg); err != nil {
		t.Fail()
	}

	t.Log("Mail sent successfully")
}
