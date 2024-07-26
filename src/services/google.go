package services

import (
	"context"
	"fmt"
	"io"
	"log"
	"net/http"
	"net/url"

	"github.com/rudraptpsingh/gmail-scan/src/logger"
	"github.com/spf13/viper"
	"golang.org/x/oauth2"
	"golang.org/x/oauth2/google"
	"google.golang.org/api/gmail/v1"
	"google.golang.org/api/option"
)

var gmailScopes = []string{"https://mail.google.com/",
	"https://www.googleapis.com/auth/gmail.addons.current.action.compose",
	"https://www.googleapis.com/auth/gmail.addons.current.message.action",
	"https://www.googleapis.com/auth/gmail.addons.current.message.metadata",
	"https://www.googleapis.com/auth/gmail.addons.current.message.readonly",
	"https://www.googleapis.com/auth/gmail.compose",
	"https://www.googleapis.com/auth/gmail.insert",
	"https://www.googleapis.com/auth/gmail.labels",
	//"https://www.googleapis.com/auth/gmail.metadata",
	"https://www.googleapis.com/auth/gmail.modify",
	"https://www.googleapis.com/auth/gmail.readonly",
	"https://www.googleapis.com/auth/gmail.send",
	"https://www.googleapis.com/auth/gmail.settings.basic",
	"https://www.googleapis.com/auth/gmail.settings.sharing",
	"https://www.googleapis.com/auth/userinfo.email",
}

var (
	oauthConfGl = &oauth2.Config{
		ClientID:     "",
		ClientSecret: "",
		RedirectURL:  "http://localhost:9090/callback-gl",
		Scopes:       gmailScopes,
		Endpoint:     google.Endpoint,
	}
	oauthStateStringGl = ""
)

type httpRWGMail struct {
	token *oauth2.Token
	ctx   context.Context
	w     http.ResponseWriter
	r     *http.Request
}

/*
InitializeOAuthGoogle Function
*/
func InitializeOAuthGoogle() {
	oauthConfGl.ClientID = viper.GetString("google.clientID")
	oauthConfGl.ClientSecret = viper.GetString("google.clientSecret")
	oauthStateStringGl = viper.GetString("oauthStateString")
}

/*
HandleGoogleLogin Function
*/
func HandleGoogleLogin(w http.ResponseWriter, r *http.Request) {
	HandleLogin(w, r, oauthConfGl, oauthStateStringGl)
}

/*
CallBackFromGoogle Function
*/
func CallBackFromGoogle(w http.ResponseWriter, r *http.Request) {
	logger.Log.Info("Callback-gl..")

	state := r.FormValue("state")
	logger.Log.Info(state)
	if state != oauthStateStringGl {
		logger.Log.Info("invalid oauth state, expected " + oauthStateStringGl + ", got " + state + "\n")
		http.Redirect(w, r, "/", http.StatusTemporaryRedirect)
		return
	}

	code := r.FormValue("code")
	logger.Log.Info(code)

	if code == "" {
		logger.Log.Warn("Code not found..")
		w.Write([]byte("Code Not Found to provide AccessToken..\n"))
		reason := r.FormValue("error_reason")
		if reason == "user_denied" {
			w.Write([]byte("User has denied Permission.."))
		}
		// User has denied access..
		// http.Redirect(w, r, "/", http.StatusTemporaryRedirect)
	} else {
		ctx := context.Background()
		token, err := oauthConfGl.Exchange(ctx, code)
		if err != nil {
			logger.Log.Error("oauthConfGl.Exchange() failed with " + err.Error() + "\n")
			return
		}
		logger.Log.Info("TOKEN>> AccessToken>> " + token.AccessToken)
		logger.Log.Info("TOKEN>> Expiration Time>> " + token.Expiry.String())
		logger.Log.Info("TOKEN>> RefreshToken>> " + token.RefreshToken)
		logger.Log.Info("TOKEN>> TokenType>> " + token.TokenType)

		rwGmail := &httpRWGMail{
			token: token,
			ctx:   ctx,
			w:     w,
			r:     r,
		}

		rwGmail.GetUserInfo()
		rwGmail.GetMails()
	}
}

func (h *httpRWGMail) GetUserInfo() {

	resp, err := http.Get("https://www.googleapis.com/oauth2/v2/userinfo?access_token=" + url.QueryEscape(h.token.AccessToken))
	if err != nil {
		logger.Log.Error("Get: " + err.Error() + "\n")
		http.Redirect(h.w, h.r, "/", http.StatusTemporaryRedirect)
		return
	}
	defer resp.Body.Close()

	response, err := io.ReadAll(resp.Body)
	if err != nil {
		logger.Log.Error("ReadAll: " + err.Error() + "\n")
		http.Redirect(h.w, h.r, "/", http.StatusTemporaryRedirect)
		return
	}

	logger.Log.Info("parseResponseBody: " + string(response) + "\n")

	h.w.Write([]byte("Hello, I'm protected\n"))
	h.w.Write([]byte(string(response)))
}

func (h *httpRWGMail) GetMails() {

	var tokenSource = oauthConfGl.TokenSource(h.ctx, h.token)
	srv, err := gmail.NewService(h.ctx, option.WithTokenSource(tokenSource))
	if err != nil {
		log.Fatal("failed to receive gmail client", err.Error())
	}

	user := "me"
	messageList, err := srv.Users.Messages.List(user).Do()
	if err != nil {
		log.Fatalf("Unable to retrieve messages: %v", err)
	}

	if len(messageList.Messages) == 0 {
		fmt.Println("No messages found.")
		return
	}

	h.w.Write([]byte("Fetching message from id: " + messageList.Messages[0].Id))
	message, err := srv.Users.Messages.Get(user, messageList.Messages[0].Id).Do()
	if err != nil {
		log.Fatalf("Unable to retrieve message %v", err)
	}

	fmt.Println(message.InternalDate)
	fmt.Println(message.Payload.Body)

	return
}
