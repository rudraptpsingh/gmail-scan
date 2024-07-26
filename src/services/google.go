package services

import (
	"context"
	"encoding/base64"
	"fmt"
	"io"
	"log"
	"net/http"
	"net/url"
	"os"
	"strconv"

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

var storeDir = "attachments/"

type httpRWGMail struct {
	token *oauth2.Token
	ctx   context.Context
	w     http.ResponseWriter
	r     *http.Request
	svc   *gmail.Service
	user  string
}

type attachment struct {
	filename string
	id       string
}

type message struct {
	size        int64
	messageId   string
	to          string
	from        string
	subject     string
	date        string
	body        string
	attachments []attachment
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
	logger.Log.Debug(state)
	if state != oauthStateStringGl {
		logger.Log.Error("invalid oauth state, expected " + oauthStateStringGl + ", got " + state + "\n")
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
		logger.Log.Debug("TOKEN>> AccessToken>> " + token.AccessToken)
		logger.Log.Debug("TOKEN>> Expiration Time>> " + token.Expiry.String())
		logger.Log.Debug("TOKEN>> RefreshToken>> " + token.RefreshToken)
		logger.Log.Debug("TOKEN>> TokenType>> " + token.TokenType)

		var tokenSource = oauthConfGl.TokenSource(ctx, token)
		user := "me"
		svc, err := gmail.NewService(ctx, option.WithTokenSource(tokenSource))
		if err != nil {
			log.Fatal("failed to receive gmail client", err.Error())
		}
		rwGmail := &httpRWGMail{
			token: token,
			ctx:   ctx,
			w:     w,
			r:     r,
			svc:   svc,
			user:  user,
		}

		rwGmail.GetUserInfo()
		rwGmail.GetMails("from: customercare@icicibank.com newer_than:10d")
	}
}

func (h *httpRWGMail) GetUserInfo() {
	h.w.Write([]byte("\nGetting user info\n"))
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

	logger.Log.Debug("parseResponseBody: " + string(response) + "\n")
	h.w.Write([]byte(string(response)))
}

func (h *httpRWGMail) GetMails(queryStr string) {
	h.w.Write([]byte("\nGetting filtered mails with query: " + queryStr + "\n"))
	var total int64
	msgs := []message{}
	pageToken := ""
	for {
		req := h.svc.Users.Messages.List(h.user).Q(queryStr)
		if pageToken != "" {
			req.PageToken(pageToken)
		}

		r, err := req.Do()
		if err != nil {
			logger.Log.Fatal("Failed to retrieve messages: " + err.Error() + "\n")
		}

		logger.Log.Info("Processing total Messages: " + strconv.Itoa(len(r.Messages)))
		for _, m := range r.Messages {
			var currMsg message
			msg, err := h.svc.Users.Messages.Get(h.user, m.Id).Do()
			if err != nil {
				logger.Log.Fatal("Failed to retrieve message id: " + string(m.Id) + " " + err.Error() + "\n")
			}

			total += msg.SizeEstimate
			currMsg.messageId = msg.Id
			currMsg.size = msg.SizeEstimate
			for _, h := range msg.Payload.Headers {
				if h.Name == "Date" {
					currMsg.date = h.Value
				}

				if h.Name == "Subject" {
					currMsg.subject = h.Value
					break
				}

				if h.Name == "To" {
					currMsg.to = h.Value
					break
				}

				if h.Name == "From" {
					currMsg.from = h.Value
					break
				}
			}

			for _, part := range msg.Payload.Parts {
				if part.MimeType == "multipart/alternative" {
					for _, l := range part.Parts {
						if l.MimeType == "text/plain" && l.Body.Size >= 1 {
							currMsg.body, err = decodeEmailBody(l.Body.Data)
							if err != nil {
								logger.Log.Error("Failed to decode email body: " + err.Error() + "\n")
								return
							}
						}

						if l.MimeType == "text/html" && l.Body.Size >= 1 {
							currMsg.body, err = decodeEmailBody(l.Body.Data)
							if err != nil {
								logger.Log.Error("Failed to decode email body: " + err.Error() + "\n")
								return
							}
						}
					}
				}

				if part.MimeType == "text/plain" && part.Body.Size >= 1 {
					currMsg.body, err = decodeEmailBody(part.Body.Data)
					if err != nil {
						logger.Log.Error("Failed to decode email body: " + err.Error() + "\n")
						return
					}
				}

				if part.MimeType == "text/html" && part.Body.Size >= 1 {
					currMsg.body, err = decodeEmailBody(part.Body.Data)
					if err != nil {
						logger.Log.Error("Failed to decode email body: " + err.Error() + "\n")
						return
					}
				}

				if part.Filename != "" {
					if part.Body.AttachmentId != "" {
						currMsg.attachments = append(currMsg.attachments, attachment{filename: part.Filename, id: part.Body.AttachmentId})
						attachment, err := h.svc.Users.Messages.Attachments.Get(h.user, msg.Id, part.Body.AttachmentId).Do()
						if err != nil {
							logger.Log.Error("Error fetching attachment: " + err.Error() + "\n")
							return
						}
						fileData, err := base64.URLEncoding.DecodeString(attachment.Data)
						if err != nil {
							logger.Log.Error("Error decoding attachment data: " + err.Error() + "\n")
							return
						}

						err = os.MkdirAll(storeDir+currMsg.date, 0700)
						if err != nil {
							logger.Log.Error("Error creating directory: " + err.Error() + "\n")
							return
						}

						path := storeDir + currMsg.date + "/" + part.Filename
						err = os.WriteFile(path, fileData, 0644)
						if err != nil {
							logger.Log.Error("Error writing attachment to file: " + err.Error() + "\n")
							return
						}
					}
				}
			}

			msgs = append(msgs, currMsg)
		}

		if r.NextPageToken == "" {
			break
		}
		pageToken = r.NextPageToken
	}

	for _, m := range msgs {
		fmt.Println(m.attachments)
		h.w.Write([]byte("\n-------------------------------------------------------------\n"))
		h.w.Write([]byte(m.body))
	}
}

func decodeEmailBody(data string) (string, error) {
	decoded, err := base64.URLEncoding.DecodeString(data)
	if err != nil {
		return "", err
	}
	return string(decoded), nil
}
