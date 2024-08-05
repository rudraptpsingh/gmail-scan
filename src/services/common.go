package services

import (
	"fmt"
	"net/http"
	"net/url"
	"regexp"
	"strconv"
	"strings"

	"github.com/rudraptpsingh/gmail-scan/src/helpers/pages"
	"github.com/rudraptpsingh/gmail-scan/src/logger"
	"github.com/xuri/excelize/v2"
	"golang.org/x/oauth2"
	"google.golang.org/api/gmail/v1"
)

var regexPatterns [2]string = [2]string{`(?i)<a[^>]+href="([^"]+)"[^>]*>[^<]*unsubscribe[^<]*</a>`, `(?i)<a[^>]+href='"['"][^>]*>.*?</a>[^<]*unsubscribe`}
var unsubFile *excelize.File

/*
HandleMain Function renders the index page when the application index route is called
*/
func HandleMain(w http.ResponseWriter, r *http.Request) {
	w.Header().Set("Content-Type", "text/html; charset=utf-8")
	w.WriteHeader(http.StatusOK)
	w.Write([]byte(pages.IndexPage))
}

/*
HandleLogin Function
*/
func HandleLogin(w http.ResponseWriter, r *http.Request, oauthConf *oauth2.Config, oauthStateString string) {
	URL, err := url.Parse(oauthConf.Endpoint.AuthURL)
	if err != nil {
		logger.Log.Error("Parse: " + err.Error())
	}
	logger.Log.Info(URL.String())
	parameters := url.Values{}
	parameters.Add("client_id", oauthConf.ClientID)
	parameters.Add("scope", strings.Join(oauthConf.Scopes, " "))
	parameters.Add("redirect_uri", oauthConf.RedirectURL)
	parameters.Add("response_type", "code")
	parameters.Add("state", oauthStateString)
	URL.RawQuery = parameters.Encode()
	url := URL.String()
	logger.Log.Info(url)
	http.Redirect(w, r, url, http.StatusTemporaryRedirect)
}

func extractUnsubscribeLink(emailBody string) (unsubscribeLink string, err error) {
	// Check if "unsubscribe" is present in the HTML body
	if !strings.Contains(strings.ToLower(emailBody), "unsubscribe") {
		err = fmt.Errorf("no unsubscribe link found in the email body")
		return
	}

	for i, pattern := range regexPatterns {
		link := GetRegexMatchStr(emailBody, pattern)
		if link != "" {
			logger.Log.Debug("Matched regex pattern " + strconv.Itoa(i))
			unsubscribeLink = link
			return
		}
	}

	err = fmt.Errorf("no unsubscribe link found in the email body")
	return
}

func GetEmailBodyFromMsg(msg *gmail.Message) (body string, err error) {
	for _, part := range msg.Payload.Parts {
		if part.MimeType == "multipart/related" {
			for _, p := range part.Parts {
				if p.MimeType == "multipart/alternative" {
					for _, l := range p.Parts {
						if l.MimeType == "text/plain" && l.Body.Size >= 1 {
							body, err = decodeEmailBody(l.Body.Data)
							if err != nil {
								logger.Log.Error("Failed to decode email body: " + err.Error() + "\n")
								return
							}
						}

						if l.MimeType == "text/html" && l.Body.Size >= 1 {
							body, err = decodeEmailBody(l.Body.Data)
							if err != nil {
								logger.Log.Error("Failed to decode email body: " + err.Error() + "\n")
								return
							}
						}
					}
				}
			}
		}

		if part.MimeType == "multipart/alternative" {
			for _, l := range part.Parts {
				if l.MimeType == "text/plain" && l.Body.Size >= 1 {
					body, err = decodeEmailBody(l.Body.Data)
					if err != nil {
						logger.Log.Error("Failed to decode email body: " + err.Error() + "\n")
						return
					}
				}

				if l.MimeType == "text/html" && l.Body.Size >= 1 {
					body, err = decodeEmailBody(l.Body.Data)
					if err != nil {
						logger.Log.Error("Failed to decode email body: " + err.Error() + "\n")
						return
					}
				}
			}
		}

		if part.MimeType == "text/plain" && part.Body.Size >= 1 {
			body, err = decodeEmailBody(part.Body.Data)
			if err != nil {
				logger.Log.Error("Failed to decode email body: " + err.Error() + "\n")
				return
			}
		}

		if part.MimeType == "text/html" && part.Body.Size >= 1 {
			body, err = decodeEmailBody(part.Body.Data)
			if err != nil {
				logger.Log.Error("Failed to decode email body: " + err.Error() + "\n")
				return
			}
		}
	}

	return
}

func GetRegexMatchStr(source, matchStr string) string {
	re := regexp.MustCompile(matchStr)
	match := re.FindStringSubmatch(source)
	if len(match) > 1 {
		return match[1]
	}

	return ""
}
