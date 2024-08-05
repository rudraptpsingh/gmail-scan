package services

import (
	"context"
	"encoding/base64"
	"encoding/csv"
	"fmt"
	"io"
	"log"
	"mime/multipart"
	"net/http"
	"net/url"
	"os"
	"path/filepath"
	"strconv"
	"strings"

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
var OAuthch chan *httpRWGMail

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
	unsubLink   string
}

func (m *message) GetAllAttachmentNames() (attachments []string) {
	for _, at := range m.attachments {
		attachments = append(attachments, at.filename)
	}
	return
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
		//rwGmail.GetMails("from: customercare@icicibank.com newer_than:10d")
		rwGmail.GetUnsubscribeList()

		// var msg message
		// msg.to = "rudra.ptp.singh@gmail.com"
		// msg.subject = "Test mail from RP"
		// msg.body = "Test Body from RP"
		// msg.attachments = append(msg.attachments, attachment{
		// 	filename: "/Users/rp/Documents/GitHub/gmail-scan/src/services/TestMail1.txt",
		// })
		// msg.attachments = append(msg.attachments, attachment{
		// 	filename: "/Users/rp/Documents/GitHub/gmail-scan/src/services/TestMail2.txt",
		// })
		// rwGmail.SendMail(msg)
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
			currMsg = h.GetMsgDetails(msg)
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

func (h *httpRWGMail) GetUnsubscribeList() {
	pageToken := ""
	var unsubList []string
	unsubFile, err := os.Create("unsublist.csv")
	defer unsubFile.Close()
	// initialize csv writer
	writer := csv.NewWriter(unsubFile)
	writer.Write([]string{"Unsubscribe link", "Email body"})
	defer writer.Flush()
	if err != nil {
		logger.Log.Error("Failed to create excel file to save unsubscribe list")
	}

	for {
		req := h.svc.Users.Messages.List(h.user)
		if pageToken != "" {
			req.PageToken(pageToken)
		}

		resp, err := req.Do()
		if err != nil {
			logger.Log.Error("Error fetching messages: " + err.Error() + "\n")
			return
		}

		logger.Log.Info("Processing total Messages: " + strconv.Itoa(len(resp.Messages)))
		for _, m := range resp.Messages {
			msg, err := h.svc.Users.Messages.Get(h.user, m.Id).Do()
			if err != nil {
				logger.Log.Error("Error fetching message: " + err.Error() + "\n")
				return
			}

			for _, header := range msg.Payload.Headers {
				if header.Name == "List-Unsubscribe" {
					body, err := GetEmailBodyFromMsg(msg)
					if err != nil || body == "" {
						logger.Log.Info("Failed to get email body from msg\n")
						continue
					}

					unsubLink, err := extractUnsubscribeLink(body)
					if err == nil {
						logger.Log.Debug("Extracted Link. " + "\n" + "Body: " + body + "\n" + "Unsubscribe link: " + unsubLink + "\n")
						unsubList = append(unsubList, unsubLink)
						h.w.Write([]byte("\n-------------------------------------------------------------\n"))
						h.w.Write([]byte("Unsubscribe Link: " + unsubLink))
						h.w.Write([]byte("\n-------------------------------------------------------------\n"))
					} else {
						logger.Log.Debug("Can't extract link. Body: " + body)
						writer.Write([]string{unsubLink, body})
					}
				}
			}

			if resp.NextPageToken == "" {
				break
			}
			pageToken = resp.NextPageToken
		}
	}
}

func (h *httpRWGMail) GetMsgDetails(msg *gmail.Message) (currMsg message) {
	currMsg.messageId = msg.Id
	currMsg.size = msg.SizeEstimate
	for _, h := range msg.Payload.Headers {
		if h.Name == "Date" {
			currMsg.date = h.Value
			break
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

		if h.Name == "List-Unsubscribe" {
			currMsg.unsubLink = h.Value
		}
	}

	body, err := GetEmailBodyFromMsg(msg)
	if err != nil {
		logger.Log.Error("Failed to get email body from message" + err.Error() + "\n")
	}

	currMsg.body = body
	currMsg.attachments, err = h.GetEmailAttachmentsFromMsg(msg)
	if err != nil {
		logger.Log.Error("Failed to get attachments from message" + "\n")
	}

	return
}

func (h *httpRWGMail) SendMail(msg message) (err error) {
	logger.Log.Debug("Sending mail\n")
	attachments := msg.GetAllAttachmentNames()
	msgBody, err := createMessageWithAttachments(msg.to, msg.subject, msg.body, attachments)
	if err != nil {
		log.Fatalf("Unable to create message: %v", err)
	}

	_, err = h.svc.Users.Messages.Send(h.user, msgBody).Do()
	if err != nil {
		logger.Log.Error("Error sending mail" + err.Error() + "\n")
		return
	}

	logger.Log.Debug("Mail sent successfully")
	return
}

func createMessageWithAttachments(to, subject, body string, filenames []string) (msg *gmail.Message, err error) {
	// Create a multipart writer
	var buf strings.Builder
	writer := multipart.NewWriter(&buf)
	boundary := writer.Boundary()

	// Write the email headers
	headers := fmt.Sprintf("From: 'me'\r\nTo: %s\r\nSubject: %s\r\nMIME-Version: 1.0\r\nContent-Type: multipart/mixed; boundary=%s\r\n\r\n", to, subject, boundary)
	buf.WriteString(headers)

	// Write the email body
	part, err := writer.CreatePart(map[string][]string{
		"Content-Type": {"text/plain; charset=UTF-8"},
	})
	if err != nil {
		return nil, err
	}
	part.Write([]byte(body))

	for _, path := range filenames {
		// Read the attachment file
		file, err := os.Open(path)
		if err != nil {
			return nil, err
		}
		defer file.Close()

		// Write the attachment
		part, err = writer.CreatePart(map[string][]string{
			"Content-Type":              {"application/octet-stream"},
			"Content-Disposition":       {fmt.Sprintf("attachment; filename=\"%s\"", filepath.Base(path))},
			"Content-Transfer-Encoding": {"base64"},
		})
		if err != nil {
			return nil, err
		}

		// Encode the file content to base64
		fileContent := make([]byte, 4096)
		for {
			n, err := file.Read(fileContent)
			if err != nil {
				break
			}
			part.Write([]byte(base64.StdEncoding.EncodeToString(fileContent[:n])))
		}
	}

	writer.Close()

	// Encode the entire message to base64
	rawMessage := base64.URLEncoding.EncodeToString([]byte(buf.String()))
	msg = &gmail.Message{
		Raw: rawMessage,
	}

	return
}

func InitGmailOAuthAndRunApp(port string) {
	// Initialize Oauth2 Services
	InitializeOAuthGoogle()

	// Routes for the application
	http.HandleFunc("/", HandleMain)
	http.HandleFunc("/login-gmail", HandleGoogleLogin)
	http.HandleFunc("/callback-gl", CallBackFromGoogle)

	logger.Log.Info("Started running on http://localhost:" + port)
	log.Fatal(http.ListenAndServe(":"+viper.GetString("port"), nil))
}

func (h *httpRWGMail) GetEmailAttachmentsFromMsg(msg *gmail.Message) (attachments []attachment, err error) {
	for _, part := range msg.Payload.Parts {
		if part.Filename != "" {
			if part.Body.AttachmentId != "" {
				attachments = append(attachments, attachment{filename: part.Filename, id: part.Body.AttachmentId})
				at, err := h.svc.Users.Messages.Attachments.Get(h.user, msg.Id, part.Body.AttachmentId).Do()
				if err != nil {
					logger.Log.Error("Error fetching attachment: " + err.Error() + "\n")
					break
				}
				fileData, err := base64.URLEncoding.DecodeString(at.Data)
				if err != nil {
					logger.Log.Error("Error decoding attachment data: " + err.Error() + "\n")
					break
				}

				err = os.MkdirAll(storeDir, 0700)
				if err != nil {
					logger.Log.Error("Error creating directory: " + err.Error() + "\n")
					break
				}

				path := storeDir + "/" + part.Filename
				err = os.WriteFile(path, fileData, 0644)
				if err != nil {
					logger.Log.Error("Error writing attachment to file: " + err.Error() + "\n")
					break
				}
			}
		}
	}

	return
}
