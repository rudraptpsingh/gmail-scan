package main

import (
	"github.com/rudraptpsingh/gmail-scan/src/configs"
	"github.com/rudraptpsingh/gmail-scan/src/logger"
	"github.com/rudraptpsingh/gmail-scan/src/services"
	"github.com/spf13/viper"
)

func main() {
	// Initialize Viper across the application
	configs.InitializeViper()

	// Initialize Logger across the application
	logger.InitializeZapCustomLogger()

	// Run app with GMail OAuth.
	services.InitGmailOAuthAndRunApp(viper.GetString("port"))
}
