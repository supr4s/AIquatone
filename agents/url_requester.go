package agents

import (
	"fmt"
	"io/ioutil"
	"net/url"
	"os"
	"strings"

	"github.com/parnurzeal/gorequest"
	"github.com/supr4s/aiquatone/core"
)

type URLRequester struct {
	session *core.Session
}

func NewURLRequester() *URLRequester {
	return &URLRequester{}
}

func (d *URLRequester) ID() string {
	return "agent:url_requester"
}

func (a *URLRequester) Register(s *core.Session) error {
	s.EventBus.SubscribeAsync(core.URL, a.OnURL, false)
	a.session = s
	return nil
}

func (a *URLRequester) OnURL(rawURL string) {
	a.session.Out.Debug("[%s] Received new URL %s\n", a.ID(), rawURL)
	a.session.WaitGroup.Add()
	go func(originalURL string) {
		defer a.session.WaitGroup.Done()

		currentURL := originalURL
		var redirectChain []string
		maxRedirects := 10

		for i := 0; i <= maxRedirects; i++ {
			http := Gorequest(a.session.Options)
			resp, _, errs := http.Get(currentURL).
				Set("User-Agent", RandomUserAgent()).
				Set("X-Forwarded-For", RandomIPv4Address()).
				Set("Via", fmt.Sprintf("1.1 %s", RandomIPv4Address())).
				Set("Forwarded", fmt.Sprintf("for=%s;proto=http;by=%s", RandomIPv4Address(), RandomIPv4Address())).End()

			if errs != nil {
				a.session.Stats.IncrementRequestFailed()
				for _, err := range errs {
					a.session.Out.Debug("[%s] Error: %v\n", a.ID(), err)
					if os.IsTimeout(err) {
						a.session.Out.Error("%s: request timeout\n", originalURL)
						return
					}
				}
				a.session.Out.Debug("%s: failed\n", originalURL)
				return
			}
			if resp != nil && resp.Body != nil {
				defer resp.Body.Close()
			}

			// If redirect with a usable Location, record and follow it.
			// A redirect without a resolvable Location is a dead end, so we
			// treat the current response as final instead of discarding it.
			if resp.StatusCode >= 300 && resp.StatusCode < 400 {
				if location := resp.Header.Get("Location"); location != "" {
					if resolvedURL, ok := resolveRedirect(currentURL, location); ok {
						a.session.Stats.IncrementResponseCode3xx()
						redirectChain = append(redirectChain, resolvedURL)
						currentURL = resolvedURL
						a.session.Out.Debug("[%s] Following redirect %s -> %s\n", a.ID(), originalURL, resolvedURL)
						continue
					}
				}
			}

			// Final response (either a non-redirect, or a redirect we cannot follow)
			a.session.Stats.IncrementRequestSuccessful()
			var status string
			if resp.StatusCode >= 500 {
				a.session.Stats.IncrementResponseCode5xx()
				status = Red(resp.Status)
			} else if resp.StatusCode >= 400 {
				a.session.Stats.IncrementResponseCode4xx()
				status = Yellow(resp.Status)
			} else if resp.StatusCode >= 300 {
				a.session.Stats.IncrementResponseCode3xx()
				status = Yellow(resp.Status)
			} else {
				a.session.Stats.IncrementResponseCode2xx()
				status = Green(resp.Status)
			}
			a.session.Out.Info("%s: %s\n", originalURL, status)

			page, err := a.createPageFromResponse(originalURL, resp)
			if err != nil {
				a.session.Out.Debug("[%s] Error: %v\n", a.ID(), err)
				a.session.Out.Error("Failed to create page for URL: %s\n", originalURL)
				return
			}

			// Tag redirects
			if len(redirectChain) > 0 {
				finalDest := redirectChain[len(redirectChain)-1]
				destURL, _ := url.Parse(finalDest)
				destHost := ""
				if destURL != nil {
					destHost = destURL.Hostname()
				}
				// Detect SSO/auth redirects
				lowerDest := strings.ToLower(finalDest)
				if strings.Contains(lowerDest, "/sso") || strings.Contains(lowerDest, "/oauth") ||
					strings.Contains(lowerDest, "/saml") || strings.Contains(lowerDest, "/cas") ||
					strings.Contains(lowerDest, "/login") || strings.Contains(lowerDest, "/signin") ||
					strings.Contains(lowerDest, "/auth") || strings.Contains(lowerDest, "/adfs") ||
					strings.Contains(lowerDest, "okta.com") || strings.Contains(lowerDest, "auth0.com") ||
					strings.Contains(lowerDest, "duosecurity.com") || strings.Contains(lowerDest, "onelogin.com") ||
					strings.Contains(lowerDest, "microsoftonline.com") || strings.Contains(lowerDest, "login.microsoft") {
					page.AddTag(fmt.Sprintf("Redirect → SSO (%s)", destHost), "redirect", "")
				} else {
					page.AddTag(fmt.Sprintf("Redirect → %s", destHost), "redirect", "")
				}
				a.session.Out.Debug("[%s] Redirect chain for %s: %v\n", a.ID(), originalURL, redirectChain)
			}

			a.writeHeaders(page)
			if *a.session.Options.SaveBody {
				a.writeBody(page, resp)
			}

			a.session.EventBus.Publish(core.URLResponsive, originalURL)
			return
		}

		// If we got here, too many redirects
		a.session.Stats.IncrementRequestFailed()
		a.session.Out.Error("%s: too many redirects\n", originalURL)
	}(rawURL)
}

// resolveRedirect resolves a (possibly relative) Location header against the
// current URL. It returns the absolute target and whether resolution succeeded.
func resolveRedirect(currentURL, location string) (string, bool) {
	locURL, err := url.Parse(location)
	if err != nil {
		return "", false
	}
	baseURL, err := url.Parse(currentURL)
	if err != nil {
		return "", false
	}
	return baseURL.ResolveReference(locURL).String(), true
}

func (a *URLRequester) createPageFromResponse(url string, resp gorequest.Response) (*core.Page, error) {
	page, err := a.session.AddPage(url)
	if err != nil {
		return nil, err
	}

	page.Status = resp.Status
	for name, value := range resp.Header {
		page.AddHeader(name, strings.Join(value, " "))
	}

	return page, nil
}

func (a *URLRequester) writeHeaders(page *core.Page) {
	filepath := fmt.Sprintf("headers/%s.txt", page.BaseFilename())
	headers := fmt.Sprintf("%s\n", page.Status)
	for _, header := range page.Headers {
		headers += fmt.Sprintf("%v: %v\n", header.Name, header.Value)
	}
	if err := ioutil.WriteFile(a.session.GetFilePath(filepath), []byte(headers), 0644); err != nil {
		a.session.Out.Debug("[%s] Error: %v\n", a.ID(), err)
		a.session.Out.Error("Failed to write HTTP response headers for %s to %s\n", page.URL, a.session.GetFilePath(filepath))
	}
	page.HeadersPath = filepath
}

func (a *URLRequester) writeBody(page *core.Page, resp gorequest.Response) {
	filepath := fmt.Sprintf("html/%s.html", page.BaseFilename())
	body, err := ioutil.ReadAll(resp.Body)
	if err != nil {
		a.session.Out.Debug("[%s] Error: %v\n", a.ID(), err)
		a.session.Out.Error("Failed to read response body for %s\n", page.URL)
		return
	}

	if err := ioutil.WriteFile(a.session.GetFilePath(filepath), body, 0644); err != nil {
		a.session.Out.Debug("[%s] Error: %v\n", a.ID(), err)
		a.session.Out.Error("Failed to write HTTP response body for %s to %s\n", page.URL, a.session.GetFilePath(filepath))
	}
	page.BodyPath = filepath
}
