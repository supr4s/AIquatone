package agents

import (
	"bytes"
	"fmt"
	"regexp"
	"strings"

	"github.com/PuerkitoBio/goquery"
	wappalyzer "github.com/projectdiscovery/wappalyzergo"
	"github.com/supr4s/aiquatone/core"
)

type URLTechnologyFingerprinter struct {
	session    *core.Session
	wappalyzer *wappalyzer.Wappalyze
}

func NewURLTechnologyFingerprinter() *URLTechnologyFingerprinter {
	return &URLTechnologyFingerprinter{}
}

func (a *URLTechnologyFingerprinter) ID() string {
	return "agent:url_technology_fingerprinter"
}

func (a *URLTechnologyFingerprinter) Register(s *core.Session) error {
	s.EventBus.SubscribeAsync(core.URLResponsive, a.OnURLResponsive, false)
	a.session = s

	wap, err := wappalyzer.New()
	if err != nil {
		a.session.Out.Fatal("Failed to initialize wappalyzer: %s\n", err)
	}
	a.wappalyzer = wap

	return nil
}

func (a *URLTechnologyFingerprinter) OnURLResponsive(url string) {
	a.session.Out.Debug("[%s] Received new responsive URL %s\n", a.ID(), url)
	page := a.session.GetPage(url)
	if page == nil {
		a.session.Out.Error("Unable to find page for URL: %s\n", url)
		return
	}

	a.session.WaitGroup.Add()
	go func(page *core.Page) {
		defer a.session.WaitGroup.Done()
		a.fingerprintWithWappalyzer(page)
		a.detectFeatures(page)
	}(page)
}

// Backend-relevant wappalyzer categories (by name)
// Only technologies in these categories will be shown in the Technologies tab
var backendCategories = map[string]bool{
	"CMS":                   true,
	"Ecommerce":             true,
	"Database managers":     true,
	"Hosting panels":        true,
	"Web frameworks":        true,
	"Web servers":           true,
	"Programming languages": true,
	"Operating systems":     true,
	"Web server extensions": true,
	"Databases":             true,
	"CI":                    true,
	"Containers":            true,
	"PaaS":                  true,
	"IaaS":                  true,
	"Reverse proxies":       true,
	"Load balancers":        true,
	"Authentication":        true,
	"Caching":               true,
	"Search engines":        true,
	"Security":              true,
	"Message boards":        true,
	"Wikis":                 true,
	"Blogs":                 true,
	"Webmail":               true,
	"Media servers":         true,
	"Network devices":       true,
	"Control systems":       true,
	"Network storage":       true,
	"DMS":                   true,
}

func (a *URLTechnologyFingerprinter) isBackendTech(info wappalyzer.AppInfo) bool {
	for _, cat := range info.Categories {
		if backendCategories[cat] {
			return true
		}
	}
	return false
}

func technologyNames(fingerprint string) (baseName string, displayName string) {
	baseName, version, hasVersion := strings.Cut(fingerprint, ":")
	displayName = baseName
	if hasVersion && version != "" {
		displayName = fmt.Sprintf("%s %s", baseName, version)
	}
	return baseName, displayName
}

func (a *URLTechnologyFingerprinter) fingerprintWithWappalyzer(page *core.Page) {
	// Build headers map in net/http format (map[string][]string)
	headers := make(map[string][]string)
	for _, h := range page.Headers {
		headers[h.Name] = append(headers[h.Name], h.Value)
	}

	// Read body
	var body []byte
	b, err := a.session.ReadFile(fmt.Sprintf("html/%s.html", page.BaseFilename()))
	if err == nil {
		body = b
	}

	// Run wappalyzer fingerprinting
	fingerprints := a.wappalyzer.FingerprintWithInfo(headers, body)

	detectedTechs := make(map[string]bool)
	emittedTechs := make(map[string]bool)
	for tech, info := range fingerprints {
		baseName, displayName := technologyNames(tech)

		detectedTechs[strings.ToLower(baseName)] = true

		// Only emit tag for backend-relevant technologies
		if !a.isBackendTech(info) {
			a.session.Out.Debug("[%s] Skipping client-side tech %s (%v) on %s\n", a.ID(), baseName, info.Categories, page.URL)
			continue
		}

		// Deduplicate by technology while retaining the detected version.
		lowerBase := strings.ToLower(baseName)
		if emittedTechs[lowerBase] {
			continue
		}
		emittedTechs[lowerBase] = true

		website := info.Website
		a.session.Out.Debug("[%s] Identified technology %s on %s\n", a.ID(), displayName, page.URL)
		page.AddTag(displayName, "info", website)
	}

	// Fallback PHP detection via headers and URL when wappalyzer misses it
	if !a.hasTechPrefix(detectedTechs, "php") {
		if a.detectPHPFallback(page, headers) {
			page.AddTag("PHP", "info", "https://www.php.net/")
			a.session.Out.Debug("[%s] Detected PHP (fallback) on %s\n", a.ID(), page.URL)
		}
	}
}

func (a *URLTechnologyFingerprinter) hasTechPrefix(techs map[string]bool, prefix string) bool {
	for tech := range techs {
		if strings.HasPrefix(tech, prefix) {
			return true
		}
	}
	return false
}

func (a *URLTechnologyFingerprinter) detectPHPFallback(page *core.Page, headers map[string][]string) bool {
	// Check X-Powered-By header
	for _, val := range headers["X-Powered-By"] {
		if strings.Contains(strings.ToLower(val), "php") {
			return true
		}
	}
	// Check Set-Cookie for PHPSESSID
	for _, val := range headers["Set-Cookie"] {
		if strings.Contains(val, "PHPSESSID") {
			return true
		}
	}
	// Check URL for .php extension
	lowerURL := strings.ToLower(page.URL)
	if strings.Contains(lowerURL, ".php") {
		return true
	}
	return false
}

// ============================================================
// Feature detection: SPA, Login, Signup, Admin
// ============================================================

func (a *URLTechnologyFingerprinter) detectFeatures(page *core.Page) {
	lowerURL := strings.ToLower(page.URL)

	// Try to load body - features can still be detected from URL alone
	var doc *goquery.Document
	var lowerBody string
	body, err := a.session.ReadFile(fmt.Sprintf("html/%s.html", page.BaseFilename()))
	if err == nil {
		lowerBody = strings.ToLower(string(body))
		if d, err := goquery.NewDocumentFromReader(bytes.NewReader(body)); err == nil {
			doc = d
		}
	}

	if a.isSPA(doc, lowerBody) {
		page.AddTag("SPA", "feature", "")
		a.session.Out.Debug("[%s] Detected SPA on %s\n", a.ID(), page.URL)
	}

	auth := a.detectAuthFeatures(doc, lowerBody, lowerURL)
	if auth.LoginPage {
		page.AddTag("Login Page", "feature", "")
		a.session.Out.Debug("[%s] Detected Login Page on %s (score: %d)\n", a.ID(), page.URL, auth.LoginScore)
	} else if auth.LoginLink {
		page.AddTag("Login Link", "feature", "")
		a.session.Out.Debug("[%s] Detected Login Link on %s (score: %d)\n", a.ID(), page.URL, auth.LoginScore)
	}

	if auth.SignupPage {
		page.AddTag("Signup Page", "feature", "")
		a.session.Out.Debug("[%s] Detected Signup Page on %s (score: %d)\n", a.ID(), page.URL, auth.SignupScore)
	} else if auth.SignupLink {
		page.AddTag("Signup Link", "feature", "")
		a.session.Out.Debug("[%s] Detected Signup Link on %s (score: %d)\n", a.ID(), page.URL, auth.SignupScore)
	}

	if auth.SSO {
		page.AddTag("SSO", "feature", "")
		if auth.SSOProvider != "" {
			page.AddTag("SSO: "+auth.SSOProvider, "feature", "")
			a.session.Out.Debug("[%s] Detected SSO provider %s on %s\n", a.ID(), auth.SSOProvider, page.URL)
		}
	}

	if auth.MFA {
		page.AddTag("MFA", "feature", "")
		a.session.Out.Debug("[%s] Detected MFA on %s\n", a.ID(), page.URL)
	}

	if auth.AuthRequired {
		page.AddTag("Auth Required", "feature", "")
		a.session.Out.Debug("[%s] Detected Auth Required on %s\n", a.ID(), page.URL)
	}

	if auth.InviteOnly {
		page.AddTag("Invite Only", "feature", "")
		a.session.Out.Debug("[%s] Detected Invite Only on %s\n", a.ID(), page.URL)
	}

	if auth.RegistrationClosed {
		page.AddTag("Registration Closed", "feature", "")
		a.session.Out.Debug("[%s] Detected Registration Closed on %s\n", a.ID(), page.URL)
	}

	if a.hasAdminPage(doc, lowerBody, lowerURL) {
		page.AddTag("Admin Page", "feature", "")
		a.session.Out.Debug("[%s] Detected Admin Page on %s\n", a.ID(), page.URL)
	}

	if a.hasAPIEndpoint(doc, lowerBody, lowerURL) {
		page.AddTag("API Endpoint", "feature", "")
		a.session.Out.Debug("[%s] Detected API Endpoint on %s\n", a.ID(), page.URL)
	}

	if a.hasDirectoryListing(doc, lowerBody, lowerURL) {
		page.AddTag("Directory Listing", "feature", "")
		a.session.Out.Debug("[%s] Detected Directory Listing on %s\n", a.ID(), page.URL)
	}

	if a.hasErrorDebugPage(doc, lowerBody, lowerURL, page) {
		page.AddTag("Error/Debug", "feature", "")
		a.session.Out.Debug("[%s] Detected Error/Debug Page on %s\n", a.ID(), page.URL)
	}

	if a.hasDefaultInstall(doc, lowerBody, lowerURL) {
		page.AddTag("Default Install", "feature", "")
		a.session.Out.Debug("[%s] Detected Default Install Page on %s\n", a.ID(), page.URL)
	}

	if a.hasFileUpload(doc, lowerBody) {
		page.AddTag("File Upload", "feature", "")
		a.session.Out.Debug("[%s] Detected File Upload on %s\n", a.ID(), page.URL)
	}

	if a.hasPasswordReset(doc, lowerBody, lowerURL) {
		page.AddTag("Password Reset", "feature", "")
		a.session.Out.Debug("[%s] Detected Password Reset on %s\n", a.ID(), page.URL)
	}

	if a.hasSensitiveExposure(doc, lowerBody, lowerURL) {
		page.AddTag("Sensitive Exposure", "feature", "")
		a.session.Out.Debug("[%s] Detected Sensitive Exposure on %s\n", a.ID(), page.URL)
	}

	if a.hasCloudStorage(doc, lowerBody, lowerURL) {
		page.AddTag("Cloud Storage", "feature", "")
		a.session.Out.Debug("[%s] Detected Cloud Storage on %s\n", a.ID(), page.URL)
	}

	if a.hasControlPanel(doc, lowerBody, lowerURL) {
		page.AddTag("Control Panel", "feature", "")
		a.session.Out.Debug("[%s] Detected Control Panel on %s\n", a.ID(), page.URL)
	}

	if a.hasPaymentPage(doc, lowerBody, lowerURL) {
		page.AddTag("Payment Page", "feature", "")
		a.session.Out.Debug("[%s] Detected Payment Page on %s\n", a.ID(), page.URL)
	}

	if a.hasOpenRedirectParam(page.URL) {
		page.AddTag("Open Redirect?", "danger", "")
		a.session.Out.Debug("[%s] Detected open-redirect parameter on %s\n", a.ID(), page.URL)
	}

	if kw := interestingTitleKeyword(page.PageTitle, doc); kw != "" {
		page.AddTag("Interesting Title", "danger", "")
		a.session.Out.Debug("[%s] Interesting title keyword %q on %s\n", a.ID(), kw, page.URL)
	}

	if kw := interestingHostnameKeyword(page.URL); kw != "" {
		page.AddTag("Interesting Hostname", "danger", "")
		a.session.Out.Debug("[%s] Interesting hostname keyword %q on %s\n", a.ID(), kw, page.URL)
	}

	if a.hasCaptcha(lowerBody) {
		page.AddTag("CAPTCHA", "feature", "")
		a.session.Out.Debug("[%s] Detected CAPTCHA on %s\n", a.ID(), page.URL)
	}

	// HTTP 401 is an authentication challenge regardless of body content.
	// Guard against a duplicate tag already added from body keywords above.
	if strings.HasPrefix(page.Status, "401") && !auth.AuthRequired {
		page.AddTag("Auth Required", "feature", "")
		a.session.Out.Debug("[%s] Detected 401 Auth Required on %s\n", a.ID(), page.URL)
	}

	// 404 classification: must run after other detections
	a.classify404(page, doc, lowerBody)
}

// --- SPA Detection ---

var spaPatterns = []*regexp.Regexp{
	regexp.MustCompile(`(?i)<div\s[^>]*id\s*=\s*["'](app|root|__next|__nuxt|ember-application|angular-app|svelte|gatsby)["']`),
	regexp.MustCompile(`(?i)\bng-app\s*=`),
	regexp.MustCompile(`(?i)\bng-controller\s*=`),
	regexp.MustCompile(`(?i)\bdata-reactroot\b`),
	regexp.MustCompile(`(?i)\bdata-react-helmet\b`),
	regexp.MustCompile(`(?i)__NEXT_DATA__`),
	regexp.MustCompile(`(?i)__NUXT__`),
	regexp.MustCompile(`(?i)window\.__INITIAL_STATE__`),
	regexp.MustCompile(`(?i)window\.__PRELOADED_STATE__`),
	regexp.MustCompile(`(?i)window\.webpackJsonp`),
}

func (a *URLTechnologyFingerprinter) isSPA(doc *goquery.Document, lowerBody string) bool {
	if lowerBody == "" || doc == nil {
		return false
	}

	for _, pattern := range spaPatterns {
		if pattern.MatchString(lowerBody) {
			return true
		}
	}

	spaFrameworks := []string{
		"react", "angular", "vue", "ember", "svelte",
		"next", "nuxt", "gatsby", "backbone", "aurelia",
		"riot", "mithril", "preact", "solid", "qwik",
		"remix", "astro",
	}
	found := false
	doc.Find("script[src]").Each(func(i int, s *goquery.Selection) {
		if found {
			return
		}
		if src, exists := s.Attr("src"); exists {
			srcLower := strings.ToLower(src)
			for _, fw := range spaFrameworks {
				if strings.Contains(srcLower, fw) {
					found = true
					return
				}
			}
		}
	})
	if found {
		return true
	}

	bodyEl := doc.Find("body")
	if bodyEl.Length() > 0 {
		children := bodyEl.Children().Not("script").Not("noscript").Not("link").Not("style")
		if children.Length() <= 2 {
			scripts := doc.Find("script[src]")
			if scripts.Length() >= 1 {
				innerText := strings.TrimSpace(bodyEl.Not("script").Text())
				if len(innerText) < 100 {
					return true
				}
			}
		}
	}

	return false
}

// --- Login Page Detection ---

var loginURLPatterns = []*regexp.Regexp{
	regexp.MustCompile(`(?i)[/\?#&]log[_-]?in`),
	regexp.MustCompile(`(?i)[/\?#&]sign[_-]?in`),
	regexp.MustCompile(`(?i)[/\?#&]auth(?:enticate|entication|orize)?(?:[/\?#&]|$)`),
	regexp.MustCompile(`(?i)[/\?#&]connexion`),
	regexp.MustCompile(`(?i)[/\?#&]sso(?:[/\?#&]|$)`),
	regexp.MustCompile(`(?i)[/\?#&]oauth`),
	regexp.MustCompile(`(?i)[/\?#&]cas[/\?#&]`),
	regexp.MustCompile(`(?i)[/\?#&]saml`),
	regexp.MustCompile(`(?i)[/\?#&]session[/\?#&]new`),
	regexp.MustCompile(`(?i)[/\?#&]user[s]?[/\?#&]sign[_-]?in`),
	regexp.MustCompile(`(?i)[/\?#&]account[/\?#&]log[_-]?in`),
	// Enterprise SSO / Identity providers
	regexp.MustCompile(`(?i)[/\?#&]adfs[/\?#&]`),
	regexp.MustCompile(`(?i)[/\?#&]idp[/\?#&]`),
	regexp.MustCompile(`(?i)[/\?#&]identity[/\?#&]`),
	regexp.MustCompile(`(?i)[/\?#&]openid[_-]?connect`),
	regexp.MustCompile(`(?i)[/\?#&]secure[_-]?login`),
	regexp.MustCompile(`(?i)[/\?#&]access[_-]?portal`),
}

var loginBodyPatterns = []*regexp.Regexp{
	// Traditional forms
	regexp.MustCompile(`(?i)<form[^>]*(?:login|log.in|signin|sign.in|auth)[^>]*>`),
	regexp.MustCompile(`(?i)<input[^>]*type\s*=\s*["']password["'][^>]*>`),
	regexp.MustCompile(`(?i)<button[^>]*>(?:[^<]*(?:log\s*in|sign\s*in|connexion|se\s+connecter|submit|enter)[^<]*)</button>`),
	regexp.MustCompile(`(?i)<input[^>]*type\s*=\s*["']submit["'][^>]*value\s*=\s*["'][^"']*(?:log\s*in|sign\s*in|connexion|enter)[^"']*["']`),
	regexp.MustCompile(`(?i)<label[^>]*>(?:[^<]*(?:password|username|email|user\s*name|e-mail)[^<]*)</label>`),
	regexp.MustCompile(`(?i)placeholder\s*=\s*["'][^"']*(?:password|username|email|user\s*name|e-mail)[^"']*["']`),
	regexp.MustCompile(`(?i)name\s*=\s*["'](?:password|passwd|user_?name|login|email|user|j_password|j_username)["']`),
	regexp.MustCompile(`(?i)autocomplete\s*=\s*["'](?:current-password|username)["']`),
	// SSO provider widgets & SDKs
	regexp.MustCompile(`(?i)okta-sign-in`),
	regexp.MustCompile(`(?i)okta-signin-widget`),
	regexp.MustCompile(`(?i)OktaSignIn`),
	regexp.MustCompile(`(?i)auth0-lock`),
	regexp.MustCompile(`(?i)Auth0Lock`),
	regexp.MustCompile(`(?i)auth0\.com/authorize`),
	regexp.MustCompile(`(?i)microsoftonline\.com`),
	regexp.MustCompile(`(?i)login\.microsoft\.com`),
	regexp.MustCompile(`(?i)adfs/ls`),
	regexp.MustCompile(`(?i)pingfederate`),
	regexp.MustCompile(`(?i)ping[_-]?identity`),
	regexp.MustCompile(`(?i)forgerock`),
	regexp.MustCompile(`(?i)keycloak`),
	regexp.MustCompile(`(?i)duosecurity`),
	regexp.MustCompile(`(?i)duo_iframe`),
	regexp.MustCompile(`(?i)onelogin`),
	// Common SSO / corporate login patterns
	regexp.MustCompile(`(?i)corporate[_\s-]*login`),
	regexp.MustCompile(`(?i)enterprise[_\s-]*login`),
	regexp.MustCompile(`(?i)employee[_\s-]*login`),
	regexp.MustCompile(`(?i)sign\s*in\s*with\s*(?:sso|saml|corporate|your\s*(?:company|organization))`),
	regexp.MustCompile(`(?i)single\s*sign[_\s-]*on`),
	// Link/anchor login buttons (JS-rendered or SPA)
	regexp.MustCompile(`(?i)<a[^>]*(?:href|onclick)[^>]*>[^<]*(?:log\s*in|sign\s*in|se\s+connecter|connexion)[^<]*</a>`),
	// Meta redirect to login
	regexp.MustCompile(`(?i)<meta[^>]*http-equiv\s*=\s*["']refresh["'][^>]*url\s*=\s*[^"']*(?:login|signin|auth|sso)`),
	// id/class attributes on containers
	regexp.MustCompile(`(?i)(?:id|class)\s*=\s*["'][^"']*(?:login[_-]?(?:form|container|wrapper|page|box|panel|modal)|sign[_-]?in[_-]?(?:form|container|wrapper|page|box))[^"']*["']`),
	// SAML forms
	regexp.MustCompile(`(?i)<input[^>]*name\s*=\s*["']SAMLResponse["']`),
	regexp.MustCompile(`(?i)<input[^>]*name\s*=\s*["']SAMLRequest["']`),
	regexp.MustCompile(`(?i)<input[^>]*name\s*=\s*["']RelayState["']`),
	// Common credential input IDs
	regexp.MustCompile(`(?i)id\s*=\s*["'](?:username|userid|user_?id|loginId|userInput|identifierId|okta-signin-username)["']`),
}

var loginTitleKeywords = []string{
	"login", "log in", "sign in", "signin",
	"authentication", "authenticate",
	"connexion", "se connecter", "authentification",
	"sso", "single sign-on", "single sign on",
	"identity", "access portal",
	"okta", "auth0",
}

func (a *URLTechnologyFingerprinter) hasLoginPage(doc *goquery.Document, lowerBody string, lowerURL string) bool {
	return a.detectAuthFeatures(doc, lowerBody, lowerURL).LoginPage
}

// --- Signup Page Detection ---

var signupURLPatterns = []*regexp.Regexp{
	regexp.MustCompile(`(?i)[/\?#&]sign[_-]?up`),
	regexp.MustCompile(`(?i)[/\?#&]register`),
	regexp.MustCompile(`(?i)[/\?#&]registration`),
	regexp.MustCompile(`(?i)[/\?#&]create[_-]?account`),
	regexp.MustCompile(`(?i)[/\?#&]inscription`),
	regexp.MustCompile(`(?i)[/\?#&]join(?:[/\?#&]|$)`),
	regexp.MustCompile(`(?i)[/\?#&]enroll`),
	regexp.MustCompile(`(?i)[/\?#&]onboarding`),
	regexp.MustCompile(`(?i)[/\?#&]new[_-]?account`),
	regexp.MustCompile(`(?i)[/\?#&]user[s]?[/\?#&]new`),
	regexp.MustCompile(`(?i)[/\?#&]user[s]?[/\?#&]sign[_-]?up`),
}

var signupBodyPatterns = []*regexp.Regexp{
	regexp.MustCompile(`(?i)<form[^>]*(?:signup|sign.up|register|registration|create.account|join)[^>]*>`),
	regexp.MustCompile(`(?i)<button[^>]*>(?:[^<]*(?:sign\s*up|register|create\s+account|join|get\s+started|s'inscrire|inscription)[^<]*)</button>`),
	regexp.MustCompile(`(?i)<input[^>]*type\s*=\s*["']submit["'][^>]*value\s*=\s*["'][^"']*(?:sign\s*up|register|create\s+account|join|get\s+started|inscription)[^"']*["']`),
	regexp.MustCompile(`(?i)<a[^>]*href\s*=\s*["'][^"']*(?:signup|sign.up|register)[^"']*["'][^>]*>(?:[^<]*(?:sign\s*up|register|create|inscription|join|get\s+started)[^<]*)</a>`),
	regexp.MustCompile(`(?i)name\s*=\s*["'](?:confirm[_-]?password|password[_-]?confirm|password2|repeat[_-]?password)["']`),
}

var signupTitleKeywords = []string{
	"sign up", "signup", "register", "registration",
	"create account", "create an account",
	"join", "get started",
	"inscription", "s'inscrire", "creer un compte",
}

func (a *URLTechnologyFingerprinter) hasSignupPage(doc *goquery.Document, lowerBody string, lowerURL string) bool {
	return a.detectAuthFeatures(doc, lowerBody, lowerURL).SignupPage
}

type authFeatureResult struct {
	LoginPage          bool
	LoginLink          bool
	SignupPage         bool
	SignupLink         bool
	SSO                bool
	SSOProvider        string
	MFA                bool
	AuthRequired       bool
	InviteOnly         bool
	RegistrationClosed bool
	LoginScore         int
	SignupScore        int
}

var loginButtonKeywords = []string{
	"log in", "login", "sign in", "signin", "connexion", "se connecter",
	"authenticate", "authentication", "continue", "access account",
}

var signupButtonKeywords = []string{
	"sign up", "signup", "register", "registration", "create account",
	"create an account", "join", "get started", "start trial", "free trial",
	"inscription", "s'inscrire", "creer un compte", "request access",
}

var credentialFieldKeywords = []string{
	"username", "user-name", "user_name", "userid", "user-id", "user_id",
	"login", "email", "e-mail", "mail", "identifier", "j_username",
	"okta-signin-username", "userinput",
}

var passwordFieldKeywords = []string{
	"password", "passwd", "pwd", "passphrase", "j_password",
	"okta-signin-password",
}

var confirmPasswordKeywords = []string{
	"confirm_password", "confirm-password", "password_confirm",
	"password-confirm", "password2", "repeat_password", "repeat-password",
	"new_password", "new-password",
}

var passwordChangeKeywords = []string{
	"change password", "change your password", "new password",
	"confirm new password", "update password", "set password",
	"changer le mot de passe", "nouveau mot de passe",
}

var authRequiredKeywords = []string{
	"authentication required", "authorization required", "login required",
	"sign in required", "please sign in", "please log in", "you need to sign in",
	"you need to log in", "must be logged in", "access denied",
	"connexion requise", "authentification requise", "acces refuse",
}

var inviteOnlyKeywords = []string{
	"invite only", "invitation only", "invite code", "invitation code",
	"request an invite", "request invite", "by invitation", "request access",
	"contact your administrator", "contact an administrator",
}

var registrationClosedKeywords = []string{
	"registration closed", "registrations are closed", "signups are closed",
	"sign ups are closed", "signup disabled", "self registration disabled",
	"not accepting new users", "not accepting registrations",
	"registration is disabled", "inscriptions fermees",
}

var mfaBodyPatterns = []*regexp.Regexp{
	regexp.MustCompile(`(?i)\b(?:mfa|2fa|otp)\b`),
	regexp.MustCompile(`(?i)multi[\s-]?factor`),
	regexp.MustCompile(`(?i)two[\s-]?factor`),
	regexp.MustCompile(`(?i)one[\s-]?time\s+(?:password|passcode|code)`),
	regexp.MustCompile(`(?i)(?:verification|security|authenticator)\s+code`),
	regexp.MustCompile(`(?i)(?:authenticator|duo)\s+(?:app|push|prompt)`),
	regexp.MustCompile(`(?i)(?:webauthn|passkey|security\s+key)`),
}

type ssoProviderPattern struct {
	Name     string
	Patterns []string
}

var ssoProviderPatterns = []ssoProviderPattern{
	{Name: "Okta", Patterns: []string{"okta-sign-in", "okta-signin-widget", "oktasignin", "okta.com"}},
	{Name: "Google", Patterns: []string{"accounts.google.com", "accounts.youtube.com", "gsi/client", "g_id_onload", "google-signin"}},
	{Name: "Auth0", Patterns: []string{"auth0-lock", "auth0lock", "auth0.com", "auth0-spa-js"}},
	{Name: "Microsoft Entra", Patterns: []string{"microsoftonline.com", "login.microsoft.com", "login.live.com", "azuread", "azure ad", "azureb2c"}},
	{Name: "ADFS", Patterns: []string{"adfs/ls", "/adfs/", "adfs."}},
	{Name: "Keycloak", Patterns: []string{"keycloak", "/realms/", "/protocol/openid-connect"}},
	{Name: "Ping Identity", Patterns: []string{"pingfederate", "pingone", "pingidentity", "ping_identity"}},
	{Name: "ForgeRock", Patterns: []string{"forgerock", "openam"}},
	{Name: "Duo", Patterns: []string{"duosecurity", "duo_iframe", "duo.com"}},
	{Name: "OneLogin", Patterns: []string{"onelogin"}},
	{Name: "AWS Cognito", Patterns: []string{"cognito-idp", "cognito.amazonaws.com", "amazoncognito.com"}},
	{Name: "Firebase Auth", Patterns: []string{"firebaseapp.com/__/auth", "firebase auth", "firebaseui-auth"}},
	{Name: "Supabase Auth", Patterns: []string{"supabase.auth", "supabase.co/auth", "gotrue"}},
	{Name: "Clerk", Patterns: []string{"clerk.accounts", "clerk-js", "clerk.com"}},
	{Name: "SAML", Patterns: []string{"samlrequest=", "samlresponse=", "saml2", "/saml/", "saml/sso", "saml/acs", "saml/metadata"}},
	{Name: "CAS", Patterns: []string{"/cas/login", "servicevalidate", "ticket-granting"}},
	{Name: "Shibboleth", Patterns: []string{"shibboleth", "shibsession"}},
}

func (a *URLTechnologyFingerprinter) detectAuthFeatures(doc *goquery.Document, lowerBody string, lowerURL string) authFeatureResult {
	result := authFeatureResult{}
	title := ""
	if doc != nil {
		title = strings.ToLower(strings.TrimSpace(doc.Find("title").Text()))
	}

	urlLooksLogin := matchAnyPattern(loginURLPatterns, lowerURL)
	urlLooksSignup := matchAnyPattern(signupURLPatterns, lowerURL)
	if urlLooksLogin {
		result.LoginScore += 35
	}
	if urlLooksSignup {
		result.SignupScore += 35
	}

	if containsAny(title, loginTitleKeywords) {
		result.LoginScore += 20
	}
	if containsAny(title, signupTitleKeywords) {
		result.SignupScore += 20
	}

	result.SSOProvider = detectSSOProvider(lowerURL, lowerBody, doc)
	if result.SSOProvider != "" || containsAny(lowerURL, []string{"oauth", "oidc", "openid", "saml", "/sso", "/cas/"}) {
		result.SSO = true
		result.LoginScore += 35
	}

	if hasMFA(lowerBody, title) {
		result.MFA = true
		result.LoginScore += 15
	}

	if containsAny(lowerBody, authRequiredKeywords) || containsAny(title, authRequiredKeywords) {
		result.AuthRequired = true
		result.LoginScore += 20
	}

	if containsAny(lowerBody, inviteOnlyKeywords) || containsAny(title, inviteOnlyKeywords) {
		result.InviteOnly = true
		result.SignupScore += 10
	}
	if containsAny(lowerBody, registrationClosedKeywords) || containsAny(title, registrationClosedKeywords) {
		result.RegistrationClosed = true
		result.SignupScore += 10
	}

	if lowerBody != "" {
		if containsAny(lowerBody, []string{
			"login-form", "login_form", "signin-form", "signin_form",
			"sign-in-form", "auth-form", "authentication-form",
			"okta-signin", "auth0-lock", "sso-login",
		}) {
			result.LoginScore += 20
		}
		if containsAny(lowerBody, []string{
			"signup-form", "signup_form", "register-form", "register_form",
			"registration-form", "create-account", "create_account",
		}) {
			result.SignupScore += 20
		}
	}

	if doc != nil {
		a.scoreAuthInputs(doc, &result)
		a.scoreAuthForms(doc, &result)
		a.scoreAuthLinks(doc, &result)
		a.scoreAuthIframes(doc, &result)
	}

	passwordReset := a.hasPasswordReset(doc, lowerBody, lowerURL)
	passwordChange := containsAny(lowerBody, passwordChangeKeywords) || containsAny(title, passwordChangeKeywords)
	suppressLoginSignup := passwordReset || passwordChange
	if suppressLoginSignup {
		result.LoginScore -= 35
		result.SignupScore -= 45
		if result.LoginScore < 0 {
			result.LoginScore = 0
		}
		if result.SignupScore < 0 {
			result.SignupScore = 0
		}
	}

	result.LoginPage = result.LoginScore >= 70 ||
		(urlLooksLogin && result.LoginScore >= 45) ||
		(result.SSO && result.LoginScore >= 55)
	// A page only counts as a "Login Link" when a real login link/target was
	// found, or the login signal both clears the bar and dominates the signup
	// signal. Credential fields (username + password) alone score high on both
	// login and signup, so a signup form must not be mislabelled as a login link.
	loginLinkByScore := result.LoginScore >= 30 && result.LoginScore > result.SignupScore
	result.LoginLink = !suppressLoginSignup && !result.LoginPage && (result.LoginLink || loginLinkByScore)

	result.SignupPage = result.SignupScore >= 65 ||
		(urlLooksSignup && result.SignupScore >= 45) ||
		(urlLooksSignup && (result.InviteOnly || result.RegistrationClosed))
	if suppressLoginSignup {
		result.SignupPage = false
	}
	signupLinkByScore := result.SignupScore >= 30 && result.SignupScore >= result.LoginScore
	result.SignupLink = !suppressLoginSignup && !result.SignupPage && (result.SignupLink || signupLinkByScore)

	return result
}

func (a *URLTechnologyFingerprinter) scoreAuthInputs(doc *goquery.Document, result *authFeatureResult) {
	hasPassword := false
	hasCredential := false
	hasEmail := false
	hasConfirmPassword := false

	doc.Find("input, textarea").Each(func(i int, s *goquery.Selection) {
		field := selectionTextAndAttrs(s, "type", "name", "id", "placeholder", "autocomplete", "aria-label", "data-testid")
		fieldType, _ := s.Attr("type")
		fieldType = strings.ToLower(fieldType)

		if fieldType == "password" || containsAny(field, passwordFieldKeywords) {
			hasPassword = true
		}
		if fieldType == "email" || containsAny(field, credentialFieldKeywords) {
			hasCredential = true
		}
		if fieldType == "email" || strings.Contains(field, "email") || strings.Contains(field, "e-mail") {
			hasEmail = true
		}
		if containsAny(field, confirmPasswordKeywords) {
			hasConfirmPassword = true
		}
		if hasMFA(field, "") {
			result.MFA = true
		}
	})

	if hasPassword {
		result.LoginScore += 25
		result.SignupScore += 15
	}
	if hasCredential {
		result.LoginScore += 25
	}
	if hasEmail {
		result.SignupScore += 15
	}
	if hasConfirmPassword {
		result.SignupScore += 30
		result.LoginScore -= 15
	}
	if hasPassword && hasCredential {
		result.LoginScore += 15
	}
	if hasPassword && hasEmail {
		result.SignupScore += 10
	}
}

func (a *URLTechnologyFingerprinter) scoreAuthForms(doc *goquery.Document, result *authFeatureResult) {
	doc.Find("form").Each(func(i int, form *goquery.Selection) {
		formMeta := selectionTextAndAttrs(form, "action", "name", "id", "class", "aria-label", "data-testid")
		formText := strings.ToLower(strings.TrimSpace(form.Text()))
		formCombined := strings.TrimSpace(formMeta + " " + formText)

		formHasPassword := false
		formHasCredential := false
		formHasEmail := false
		formHasConfirmPassword := false
		form.Find("input, textarea").Each(func(i int, input *goquery.Selection) {
			field := selectionTextAndAttrs(input, "type", "name", "id", "placeholder", "autocomplete", "aria-label", "data-testid")
			fieldType, _ := input.Attr("type")
			fieldType = strings.ToLower(fieldType)
			if fieldType == "password" || containsAny(field, passwordFieldKeywords) {
				formHasPassword = true
			}
			if fieldType == "email" || containsAny(field, credentialFieldKeywords) {
				formHasCredential = true
			}
			if fieldType == "email" || strings.Contains(field, "email") || strings.Contains(field, "e-mail") {
				formHasEmail = true
			}
			if containsAny(field, confirmPasswordKeywords) {
				formHasConfirmPassword = true
			}
		})

		if containsAny(formCombined, loginButtonKeywords) || matchAnyPattern(loginURLPatterns, formCombined) {
			result.LoginScore += 25
		}
		if containsAny(formCombined, signupButtonKeywords) || matchAnyPattern(signupURLPatterns, formCombined) {
			result.SignupScore += 25
		}
		if formHasPassword && formHasCredential {
			result.LoginScore += 35
		}
		if formHasPassword && formHasEmail {
			result.SignupScore += 20
		}
		if formHasConfirmPassword {
			result.SignupScore += 35
			result.LoginScore -= 20
		}
	})
}

func (a *URLTechnologyFingerprinter) scoreAuthLinks(doc *goquery.Document, result *authFeatureResult) {
	doc.Find("a[href], button, input[type='submit'], input[type=\"submit\"], [role='button'], [role=\"button\"]").Each(func(i int, s *goquery.Selection) {
		text := selectionTextAndAttrs(s, "href", "value", "name", "id", "class", "aria-label", "title", "data-testid")
		href, _ := s.Attr("href")
		href = strings.ToLower(href)

		loginText := containsAny(text, loginButtonKeywords)
		signupText := containsAny(text, signupButtonKeywords)
		loginTarget := matchAnyPattern(loginURLPatterns, href) || containsAny(href, []string{"/auth", "/sso", "oauth", "saml", "openid"})
		signupTarget := matchAnyPattern(signupURLPatterns, href)

		if loginText || loginTarget {
			result.LoginLink = true
		}
		if signupText || signupTarget {
			result.SignupLink = true
		}
		if loginText && loginTarget {
			result.LoginScore += 15
		} else if loginText || loginTarget {
			result.LoginScore += 8
		}
		if signupText && signupTarget {
			result.SignupScore += 15
		} else if signupText || signupTarget {
			result.SignupScore += 8
		}
		if hasMFA(text, "") {
			result.MFA = true
		}
	})
}

func (a *URLTechnologyFingerprinter) scoreAuthIframes(doc *goquery.Document, result *authFeatureResult) {
	doc.Find("iframe[src]").Each(func(i int, s *goquery.Selection) {
		src := selectionTextAndAttrs(s, "src", "name", "id", "title", "class")
		if containsAny(src, []string{"login", "signin", "auth", "sso", "oauth", "saml", "okta", "adfs", "microsoftonline", "keycloak"}) {
			result.LoginScore += 25
			result.LoginLink = true
		}
	})
}

func matchAnyPattern(patterns []*regexp.Regexp, value string) bool {
	if value == "" {
		return false
	}
	for _, pattern := range patterns {
		if pattern.MatchString(value) {
			return true
		}
	}
	return false
}

func containsAny(value string, needles []string) bool {
	if value == "" {
		return false
	}
	for _, needle := range needles {
		if needle != "" && strings.Contains(value, needle) {
			return true
		}
	}
	return false
}

func selectionTextAndAttrs(s *goquery.Selection, attrs ...string) string {
	parts := []string{strings.ToLower(strings.TrimSpace(s.Text()))}
	for _, attr := range attrs {
		if value, exists := s.Attr(attr); exists {
			parts = append(parts, strings.ToLower(value))
		}
	}
	return strings.Join(parts, " ")
}

func hasMFA(lowerBody string, title string) bool {
	text := strings.TrimSpace(lowerBody + " " + title)
	if text == "" {
		return false
	}
	// autocomplete="username webauthn" is the browser passkey autofill hint
	// present on most modern login forms; it does not mean MFA is enforced.
	text = strings.ReplaceAll(text, "username webauthn", "username")
	for _, pattern := range mfaBodyPatterns {
		if pattern.MatchString(text) {
			return true
		}
	}
	return false
}

func detectSSOProvider(lowerURL string, lowerBody string, doc *goquery.Document) string {
	text := strings.TrimSpace(lowerURL + " " + lowerBody)
	if doc != nil {
		doc.Find("script[src], iframe[src], form[action], a[href], link[href]").Each(func(i int, s *goquery.Selection) {
			text += " " + selectionTextAndAttrs(s, "src", "href", "action", "id", "class", "name")
		})
	}

	for _, provider := range ssoProviderPatterns {
		for _, pattern := range provider.Patterns {
			if strings.Contains(text, strings.ToLower(pattern)) {
				return provider.Name
			}
		}
	}
	return ""
}

// --- Admin Page Detection ---

var adminURLPatterns = []*regexp.Regexp{
	regexp.MustCompile(`(?i)[/\?#&]admin(?:istrat(?:or|ion))?(?:[/\?#&]|$)`),
	regexp.MustCompile(`(?i)[/\?#&]wp-admin`),
	regexp.MustCompile(`(?i)[/\?#&]backend(?:[/\?#&]|$)`),
	regexp.MustCompile(`(?i)[/\?#&]dashboard(?:[/\?#&]|$)`),
	regexp.MustCompile(`(?i)[/\?#&]console(?:[/\?#&]|$)`),
	regexp.MustCompile(`(?i)[/\?#&]manage(?:ment|r)?(?:[/\?#&]|$)`),
	regexp.MustCompile(`(?i)[/\?#&]panel(?:[/\?#&]|$)`),
	regexp.MustCompile(`(?i)[/\?#&]control[_-]?panel`),
	regexp.MustCompile(`(?i)[/\?#&]cpanel`),
	regexp.MustCompile(`(?i)[/\?#&]backoffice`),
	regexp.MustCompile(`(?i)[/\?#&]back[_-]?office`),
	regexp.MustCompile(`(?i)[/\?#&]cms(?:[/\?#&]|$)`),
	regexp.MustCompile(`(?i)[/\?#&]portal(?:[/\?#&]|$)`),
	regexp.MustCompile(`(?i)[/\?#&]phpmyadmin`),
	regexp.MustCompile(`(?i)[/\?#&]adminer`),
	regexp.MustCompile(`(?i)[/\?#&]webmin`),
}

// adminKeywordPattern matches whole admin-related words only. Substring
// matching produced false positives such as "administrezi" (Romanian),
// "badminton", "suggestion" (for "gestion") and "top management".
var adminKeywordPattern = regexp.MustCompile(`(?i)\b(?:admin|administrator|administration|dashboard|control\s*panel|back[\s-]?office|management\s+console|tableau\s+de\s+bord|panneau\s+d'administration)\b`)

// Headings longer than this are article titles or marketing copy, not the
// name of an admin interface.
const adminHeadingMaxLength = 48

func (a *URLTechnologyFingerprinter) hasAdminPage(doc *goquery.Document, lowerBody string, lowerURL string) bool {
	for _, pattern := range adminURLPatterns {
		if pattern.MatchString(lowerURL) {
			return true
		}
	}

	if doc == nil {
		return false
	}

	title := strings.TrimSpace(doc.Find("title").Text())
	if adminKeywordPattern.MatchString(title) {
		return true
	}

	found := false
	doc.Find("h1, h2, h3").EachWithBreak(func(i int, h *goquery.Selection) bool {
		text := strings.TrimSpace(h.Text())
		if len(text) <= adminHeadingMaxLength && adminKeywordPattern.MatchString(text) {
			found = true
			return false
		}
		return true
	})
	return found
}

// --- API Endpoint Detection ---

var apiURLPatterns = []*regexp.Regexp{
	regexp.MustCompile(`(?i)[/\?#&]api[/\?#&v]`),
	regexp.MustCompile(`(?i)[/\?#&]graphql`),
	regexp.MustCompile(`(?i)[/\?#&]graphiql`),
	regexp.MustCompile(`(?i)[/\?#&]swagger`),
	regexp.MustCompile(`(?i)[/\?#&]openapi`),
	regexp.MustCompile(`(?i)[/\?#&]api-docs`),
	regexp.MustCompile(`(?i)[/\?#&]redoc`),
	regexp.MustCompile(`(?i)[/\?#&]rest[/\?#&]`),
	regexp.MustCompile(`(?i)[/\?#&]v[1-9][/\?#&]`),
	regexp.MustCompile(`(?i)[/\?#&]jsonrpc`),
	regexp.MustCompile(`(?i)[/\?#&]xmlrpc`),
	regexp.MustCompile(`(?i)[/\?#&]soap`),
	regexp.MustCompile(`(?i)[/\?#&]wsdl`),
	regexp.MustCompile(`(?i)[/\?#&]grpc`),
}

var apiBodyPatterns = []*regexp.Regexp{
	regexp.MustCompile(`(?i)swagger[\s\-]?ui`),
	regexp.MustCompile(`(?i)<title>[^<]*(?:swagger|api\s+doc|graphql|redoc|api\s+explorer|api\s+reference)[^<]*</title>`),
	regexp.MustCompile(`(?i)"openapi"\s*:\s*"`),
	regexp.MustCompile(`(?i)"swagger"\s*:\s*"`),
	regexp.MustCompile(`(?i)graphql\s*playground`),
	regexp.MustCompile(`(?i)graphiql`),
	regexp.MustCompile(`(?i)api\s*explorer`),
	regexp.MustCompile(`(?i)<div[^>]*id\s*=\s*["']swagger`),
	regexp.MustCompile(`(?i)redoc\.standalone`),
}

func (a *URLTechnologyFingerprinter) hasAPIEndpoint(doc *goquery.Document, lowerBody string, lowerURL string) bool {
	for _, pattern := range apiURLPatterns {
		if pattern.MatchString(lowerURL) {
			return true
		}
	}

	if lowerBody != "" {
		for _, pattern := range apiBodyPatterns {
			if pattern.MatchString(lowerBody) {
				return true
			}
		}
	}

	// Check for JSON response (Content-Type already in headers but also check body)
	if lowerBody != "" && len(lowerBody) > 1 {
		trimmed := strings.TrimSpace(lowerBody)
		if (strings.HasPrefix(trimmed, "{") && strings.HasSuffix(trimmed, "}")) ||
			(strings.HasPrefix(trimmed, "[") && strings.HasSuffix(trimmed, "]")) {
			return true
		}
	}

	return false
}

// --- Directory Listing Detection ---

var dirListingBodyPatterns = []*regexp.Regexp{
	regexp.MustCompile(`(?i)<title>index of /`),
	regexp.MustCompile(`(?i)<h1>index of /`),
	regexp.MustCompile(`(?i)<title>directory listing`),
	regexp.MustCompile(`(?i)>\[to parent directory\]<`),
	regexp.MustCompile(`(?i)<pre><a href="\?C=`),
	regexp.MustCompile(`(?i)<title>directory of /`),
	regexp.MustCompile(`(?i)mod_autoindex`),
	regexp.MustCompile(`(?i)<address>apache/`),
	regexp.MustCompile(`(?i)<title>\s*directory:\s*/`),
	regexp.MustCompile(`(?i)class="indexcol`),
	regexp.MustCompile(`(?i)<a href="[^"]*/">[^<]*/<`),
}

func (a *URLTechnologyFingerprinter) hasDirectoryListing(doc *goquery.Document, lowerBody string, lowerURL string) bool {
	if lowerBody != "" {
		for _, pattern := range dirListingBodyPatterns {
			if pattern.MatchString(lowerBody) {
				return true
			}
		}
	}

	if doc != nil {
		title := strings.ToLower(doc.Find("title").Text())
		if strings.HasPrefix(title, "index of") || strings.HasPrefix(title, "directory listing") ||
			strings.HasPrefix(title, "directory of") {
			return true
		}
	}

	return false
}

// --- Error/Debug Page Detection ---

var errorDebugBodyPatterns = []*regexp.Regexp{
	// Stack traces
	regexp.MustCompile(`(?i)(?:at\s+[\w\.$]+\([\w\.]+:\d+\))`),
	regexp.MustCompile(`(?i)traceback\s*\(most recent call`),
	regexp.MustCompile(`(?i)stack\s*trace:`),
	regexp.MustCompile(`(?i)uncaught\s+exception`),
	regexp.MustCompile(`(?i)fatal\s+error:`),
	// PHP errors
	regexp.MustCompile(`(?i)<b>(?:fatal|parse|notice|warning)\s+error</b>:\s+`),
	regexp.MustCompile(`(?i)on line <b>\d+</b>`),
	regexp.MustCompile(`(?i)call stack:.*#\d+`),
	// Java/Tomcat
	regexp.MustCompile(`(?i)java\.lang\.\w+exception`),
	regexp.MustCompile(`(?i)\bat\s+org\.apache\.\w`),
	regexp.MustCompile(`(?i)javax\.servlet\.\w*exception`),
	// .NET
	regexp.MustCompile(`(?i)system\.web\.\w+exception`),
	regexp.MustCompile(`(?i)asp\.net.*unhandled exception`),
	regexp.MustCompile(`(?i)server error in.*application`),
	regexp.MustCompile(`(?i)\[HttpException\]`),
	regexp.MustCompile(`(?i)runtime error</title>`),
	// Python
	regexp.MustCompile(`(?i)django\.core\.exceptions`),
	regexp.MustCompile(`(?i)flask\.debughelpers`),
	regexp.MustCompile(`(?i)werkzeug\.exceptions`),
	regexp.MustCompile(`(?i)the debugger caught an exception`),
	// Ruby
	regexp.MustCompile(`(?i)actioncontroller::routing`),
	regexp.MustCompile(`(?i)rails error`),
	regexp.MustCompile(`(?i)better errors`),
	// Debug mode indicators
	regexp.MustCompile(`(?i)debug\s+mode\s+is\s+on`),
	regexp.MustCompile(`(?i)xdebug`),
	regexp.MustCompile(`(?i)laravel.*whoops`),
	regexp.MustCompile(`(?i)symfony.*profiler`),
	// SQL errors
	regexp.MustCompile(`(?i)sql\s*syntax.*mysql`),
	regexp.MustCompile(`(?i)unclosed\s+quotation\s+mark`),
	regexp.MustCompile(`(?i)you have an error in your sql`),
	regexp.MustCompile(`(?i)pg_query\(\):`),
	regexp.MustCompile(`(?i)sqlite3?\.OperationalError`),
	regexp.MustCompile(`(?i)microsoft ole db provider for sql`),
	regexp.MustCompile(`(?i)odbc\s+sql\s+server\s+driver`),
}

func (a *URLTechnologyFingerprinter) hasErrorDebugPage(doc *goquery.Document, lowerBody string, lowerURL string, page *core.Page) bool {
	// Skip standard HTTP error responses (403, 503, etc.) - we only want actual debug/dev info leaks
	if page != nil && page.Status != "" {
		statusCode := 0
		fmt.Sscanf(page.Status, "%d", &statusCode)
		// For 4xx/5xx, only flag if there are strong debug indicators (stack traces, source code)
		if statusCode >= 400 {
			return a.hasStrongDebugIndicators(lowerBody)
		}
	}

	if lowerBody != "" {
		for _, pattern := range errorDebugBodyPatterns {
			if pattern.MatchString(lowerBody) {
				return true
			}
		}
	}

	if doc != nil {
		title := strings.ToLower(doc.Find("title").Text())
		// Only match specific debug-related titles, not generic "error" pages
		if strings.Contains(title, "whoops") || strings.Contains(title, "stack trace") ||
			strings.Contains(title, "debug") || strings.Contains(title, "exception in") ||
			strings.Contains(title, "unhandled exception") || strings.Contains(title, "runtime error") {
			return true
		}
	}

	return false
}

// hasStrongDebugIndicators checks for patterns that indicate real debug/dev info leak
// Used for 4xx/5xx pages where we need to be more strict to avoid false positives
func (a *URLTechnologyFingerprinter) hasStrongDebugIndicators(lowerBody string) bool {
	if lowerBody == "" {
		return false
	}
	strongPatterns := []*regexp.Regexp{
		// Stack traces with file paths and line numbers
		regexp.MustCompile(`(?i)(?:at\s+[\w\.$]+\([\w\.]+:\d+\))`),
		regexp.MustCompile(`(?i)traceback\s*\(most recent call`),
		// PHP errors with file paths
		regexp.MustCompile(`(?i)<b>(?:fatal|parse)\s+error</b>:\s+`),
		regexp.MustCompile(`(?i)on line <b>\d+</b>`),
		// Debug mode frameworks
		regexp.MustCompile(`(?i)laravel.*whoops`),
		regexp.MustCompile(`(?i)symfony.*profiler`),
		regexp.MustCompile(`(?i)the debugger caught an exception`),
		regexp.MustCompile(`(?i)werkzeug\.exceptions`),
		regexp.MustCompile(`(?i)xdebug`),
		// SQL errors exposing queries
		regexp.MustCompile(`(?i)you have an error in your sql`),
		regexp.MustCompile(`(?i)unclosed\s+quotation\s+mark`),
		regexp.MustCompile(`(?i)pg_query\(\):`),
		// Source code exposure
		regexp.MustCompile(`(?i)debug\s+mode\s+is\s+on`),
	}
	for _, pattern := range strongPatterns {
		if pattern.MatchString(lowerBody) {
			return true
		}
	}
	return false
}

// --- Default Install Page Detection ---

var defaultInstallBodyPatterns = []*regexp.Regexp{
	// Apache
	regexp.MustCompile(`(?i)apache2?\s+(debian|ubuntu|centos|fedora|red\s*hat)\s+default\s+page`),
	regexp.MustCompile(`(?i)<title>apache2?\s+(debian|ubuntu|centos)?\s*default\s+page`),
	regexp.MustCompile(`(?i)it works!.*this is the default`),
	// Nginx
	regexp.MustCompile(`(?i)welcome to nginx`),
	regexp.MustCompile(`(?i)<title>welcome to nginx</title>`),
	// IIS
	regexp.MustCompile(`(?i)iis\s+windows\s+server`),
	regexp.MustCompile(`(?i)<title>iis\s+\d+</title>`),
	regexp.MustCompile(`(?i)<title>iis windows server</title>`),
	// Tomcat
	regexp.MustCompile(`(?i)<title>apache tomcat`),
	regexp.MustCompile(`(?i)if you're seeing this.*you've.*successfully.*installed.*tomcat`),
	regexp.MustCompile(`(?i)congratulations.*tomcat`),
	// Other
	regexp.MustCompile(`(?i)<title>test page for.*http server`),
	regexp.MustCompile(`(?i)<title>welcome to.*the default`),
	regexp.MustCompile(`(?i)phpinfo\(\)`),
	regexp.MustCompile(`(?i)<title>phpinfo\(\)</title>`),
	regexp.MustCompile(`(?i)<h1[^>]*>phpinfo\(\)</h1>`),
	regexp.MustCompile(`(?i)congratulations.*your new.*site`),
	regexp.MustCompile(`(?i)<title>plesk`),
	regexp.MustCompile(`(?i)<title>cPanel`),
	regexp.MustCompile(`(?i)<title>webmin`),
	regexp.MustCompile(`(?i)this is a default index page`),
	// Frameworks default
	regexp.MustCompile(`(?i)laravel.*welcome`),
	regexp.MustCompile(`(?i)symfony.*profiler`),
	regexp.MustCompile(`(?i)<title>welcome to rails</title>`),
	regexp.MustCompile(`(?i)congratulations.*you.*rails`),
	regexp.MustCompile(`(?i)<title>express</title>`),
	// CMS setup
	regexp.MustCompile(`(?i)wordpress.*installation`),
	regexp.MustCompile(`(?i)wp-admin/install\.php`),
	regexp.MustCompile(`(?i)joomla.*setup`),
	regexp.MustCompile(`(?i)drupal.*installation`),
}

func (a *URLTechnologyFingerprinter) hasDefaultInstall(doc *goquery.Document, lowerBody string, lowerURL string) bool {
	if lowerBody != "" {
		for _, pattern := range defaultInstallBodyPatterns {
			if pattern.MatchString(lowerBody) {
				return true
			}
		}
	}

	return false
}

// --- File Upload Detection ---

var fileUploadBodyPatterns = []*regexp.Regexp{
	// Structural, high-confidence signals only. Greedy ".*file.*" text
	// patterns were removed: they match across minified JS bundles and
	// produce false positives on almost every modern page.
	regexp.MustCompile(`(?i)<input[^>]*type\s*=\s*["']file["']`),
	regexp.MustCompile(`(?i)enctype\s*=\s*["']multipart/form-data["']`),
	regexp.MustCompile(`(?i)\bdropzone\b`),
	regexp.MustCompile(`(?i)class\s*=\s*["'][^"']*(?:file[_-]?upload|upload[_-]?(?:file|zone|area|dropzone))[^"']*["']`),
	regexp.MustCompile(`(?i)id\s*=\s*["'][^"']*(?:file[_-]?upload|upload[_-]?(?:file|zone|area))[^"']*["']`),
}

func (a *URLTechnologyFingerprinter) hasFileUpload(doc *goquery.Document, lowerBody string) bool {
	if lowerBody != "" {
		for _, pattern := range fileUploadBodyPatterns {
			if pattern.MatchString(lowerBody) {
				return true
			}
		}
	}

	if doc != nil {
		found := false
		doc.Find("input[type='file'], input[type=\"file\"]").Each(func(i int, s *goquery.Selection) {
			found = true
		})
		if found {
			return true
		}
	}

	return false
}

// --- Password Reset Detection ---

var passwordResetURLPatterns = []*regexp.Regexp{
	regexp.MustCompile(`(?i)[/\?#&](?:forgot|reset|recover)[_-]?password`),
	regexp.MustCompile(`(?i)[/\?#&]password[_-]?(?:forgot|reset|recover)`),
	regexp.MustCompile(`(?i)[/\?#&]forgot[_-]?(?:pass|pwd)`),
	regexp.MustCompile(`(?i)[/\?#&]account[_-]?recover`),
	regexp.MustCompile(`(?i)[/\?#&]reset[_-]?account`),
	regexp.MustCompile(`(?i)[/\?#&]mot[_-]?de[_-]?passe[_-]?oublie`),
}

var passwordResetBodyPatterns = []*regexp.Regexp{
	regexp.MustCompile(`(?i)forgot\s+(?:your\s+)?password`),
	regexp.MustCompile(`(?i)reset\s+(?:your\s+)?password`),
	regexp.MustCompile(`(?i)recover\s+(?:your\s+)?(?:password|account)`),
	regexp.MustCompile(`(?i)forgotten?\s+password`),
	regexp.MustCompile(`(?i)lost\s+password`),
	regexp.MustCompile(`(?i)password\s+recovery`),
	regexp.MustCompile(`(?i)can'?t\s+(?:access|sign\s+in|log\s+in)`),
	regexp.MustCompile(`(?i)trouble\s+(?:signing|logging)\s+in`),
	regexp.MustCompile(`(?i)mot\s+de\s+passe\s+oubli[eé]`),
	regexp.MustCompile(`(?i)r[eé]initialiser.*mot\s+de\s+passe`),
}

func (a *URLTechnologyFingerprinter) hasPasswordReset(doc *goquery.Document, lowerBody string, lowerURL string) bool {
	for _, pattern := range passwordResetURLPatterns {
		if pattern.MatchString(lowerURL) {
			return true
		}
	}

	if lowerBody != "" {
		for _, pattern := range passwordResetBodyPatterns {
			if pattern.MatchString(lowerBody) {
				return true
			}
		}
	}

	if doc != nil {
		title := strings.ToLower(doc.Find("title").Text())
		if strings.Contains(title, "forgot password") || strings.Contains(title, "reset password") ||
			strings.Contains(title, "recover password") || strings.Contains(title, "password recovery") ||
			strings.Contains(title, "mot de passe oubli") {
			return true
		}
	}

	return false
}

// --- Sensitive Exposure Detection ---

var sensitiveURLPatterns = []*regexp.Regexp{
	// Version control
	regexp.MustCompile(`(?i)/\.git(?:/|$)`),
	regexp.MustCompile(`(?i)/\.svn(?:/|$)`),
	regexp.MustCompile(`(?i)/\.hg(?:/|$)`),
	regexp.MustCompile(`(?i)/\.bzr(?:/|$)`),
	// Credentials / keys frequently left exposed
	regexp.MustCompile(`(?i)/\.ssh(?:/|$)`),
	regexp.MustCompile(`(?i)/id_(?:rsa|dsa|ecdsa|ed25519)(?:\.pub)?$`),
	regexp.MustCompile(`(?i)/\.aws/credentials`),
	regexp.MustCompile(`(?i)/\.git-credentials`),
	regexp.MustCompile(`(?i)/\.netrc`),
	regexp.MustCompile(`(?i)/\.ds_store`),
	regexp.MustCompile(`(?i)/id_rsa`),
	// Environment / config files
	regexp.MustCompile(`(?i)/\.env`),
	regexp.MustCompile(`(?i)/\.htaccess`),
	regexp.MustCompile(`(?i)/\.htpasswd`),
	regexp.MustCompile(`(?i)/\.npmrc`),
	regexp.MustCompile(`(?i)/\.dockerenv`),
	regexp.MustCompile(`(?i)/web\.config`),
	regexp.MustCompile(`(?i)/wp-config`),
	regexp.MustCompile(`(?i)/config\.(?:php|yml|yaml|json|xml|ini|inc|bak)`),
	regexp.MustCompile(`(?i)/settings\.(?:php|py|json|yml|yaml)`),
	regexp.MustCompile(`(?i)/application\.(?:properties|yml|yaml)`),
	// Backup files
	regexp.MustCompile(`(?i)/(?:backup|bak|old|copy|save|orig|dump|archive)(?:/|\.)`),
	regexp.MustCompile(`(?i)\.(?:bak|backup|old|orig|save|swp|swo|tmp|temp)$`),
	regexp.MustCompile(`(?i)\.sql$`),
	regexp.MustCompile(`(?i)\.(?:tar|tar\.gz|tgz|zip|rar|7z)$`),
	// Logs
	regexp.MustCompile(`(?i)/(?:log|logs|error[_-]?log|access[_-]?log)(?:/|\.)`),
	regexp.MustCompile(`(?i)\.log$`),
	// Debug/info
	regexp.MustCompile(`(?i)/phpinfo`),
	regexp.MustCompile(`(?i)/server-status`),
	regexp.MustCompile(`(?i)/server-info`),
	regexp.MustCompile(`(?i)/debug`),
	regexp.MustCompile(`(?i)/trace`),
	regexp.MustCompile(`(?i)/actuator`),
	regexp.MustCompile(`(?i)/elmah`),
	regexp.MustCompile(`(?i)/_profiler`),
	// Sensitive endpoints
	regexp.MustCompile(`(?i)/test(?:\.php|\.asp|\.jsp)?$`),
	regexp.MustCompile(`(?i)/temp(?:/|$)`),
	regexp.MustCompile(`(?i)/private(?:/|$)`),
	regexp.MustCompile(`(?i)/internal(?:/|$)`),
	regexp.MustCompile(`(?i)/secret(?:/|$)`),
	regexp.MustCompile(`(?i)/credentials`),
	regexp.MustCompile(`(?i)/token`),
}

var sensitiveBodyPatterns = []*regexp.Regexp{
	regexp.MustCompile(`(?i)phpinfo\(\)`),
	regexp.MustCompile(`(?i)DB_PASSWORD|DB_HOST|DB_USERNAME`),
	regexp.MustCompile(`(?i)MYSQL_ROOT_PASSWORD`),
	// api_key is deliberately excluded: public search/maps/analytics keys
	// are embedded in almost every marketing page. The word boundary keeps
	// identifiers such as "ghostsearchapikey" from matching.
	regexp.MustCompile(`(?i)\b(?:access_?key|secret_?key|private_?key|client_?secret|api_?secret)\s*[:=]`),
	regexp.MustCompile(`(?i)-----BEGIN (?:RSA |DSA |EC )?PRIVATE KEY-----`),
	regexp.MustCompile(`(?i)-----BEGIN CERTIFICATE-----`),
	regexp.MustCompile(`(?i)AWS_ACCESS_KEY_ID`),
	regexp.MustCompile(`(?i)AWS_SECRET_ACCESS_KEY`),
	regexp.MustCompile(`(?i)<title>environment variables</title>`),
	regexp.MustCompile(`(?i)ref:\s+refs/heads/`),
	regexp.MustCompile(`(?i)\[core\].*repositoryformatversion`),
}

func (a *URLTechnologyFingerprinter) hasSensitiveExposure(doc *goquery.Document, lowerBody string, lowerURL string) bool {
	for _, pattern := range sensitiveURLPatterns {
		if pattern.MatchString(lowerURL) {
			return true
		}
	}

	if lowerBody != "" {
		for _, pattern := range sensitiveBodyPatterns {
			if pattern.MatchString(lowerBody) {
				return true
			}
		}
	}

	return false
}

// --- Cloud Storage Detection ---

var cloudStorageURLPatterns = []*regexp.Regexp{
	// AWS S3
	regexp.MustCompile(`(?i)s3[.\-](?:us|eu|ap|sa|ca|me|af|cn)-`),
	regexp.MustCompile(`(?i)\.s3\.amazonaws\.com`),
	regexp.MustCompile(`(?i)s3://`),
	regexp.MustCompile(`(?i)s3\.amazonaws\.com/`),
	// Google Cloud Storage
	regexp.MustCompile(`(?i)storage\.googleapis\.com`),
	regexp.MustCompile(`(?i)storage\.cloud\.google\.com`),
	regexp.MustCompile(`(?i)\.storage\.googleapis\.com`),
	// Azure Blob
	regexp.MustCompile(`(?i)\.blob\.core\.windows\.net`),
	regexp.MustCompile(`(?i)\.file\.core\.windows\.net`),
	regexp.MustCompile(`(?i)\.queue\.core\.windows\.net`),
	regexp.MustCompile(`(?i)\.table\.core\.windows\.net`),
	// DigitalOcean Spaces
	regexp.MustCompile(`(?i)\.digitaloceanspaces\.com`),
	// Alibaba OSS
	regexp.MustCompile(`(?i)\.oss-[\w-]+\.aliyuncs\.com`),
	// Backblaze B2
	regexp.MustCompile(`(?i)f\d+\.backblazeb2\.com`),
	// MinIO — anchored on a path/host/port boundary so it does not match
	// substrings like "dominio" or "condominio" on non-English sites.
	regexp.MustCompile(`(?i)[/.:]minio(?:[/.:-]|$)`),
}

var cloudStorageBodyPatterns = []*regexp.Regexp{
	regexp.MustCompile(`(?i)s3\.amazonaws\.com`),
	regexp.MustCompile(`(?i)storage\.googleapis\.com`),
	regexp.MustCompile(`(?i)\.blob\.core\.windows\.net`),
	regexp.MustCompile(`(?i)\.digitaloceanspaces\.com`),
	regexp.MustCompile(`(?i)<ListBucketResult`),
	regexp.MustCompile(`(?i)<ListAllMyBucketsResult`),
	regexp.MustCompile(`(?i)NoSuchBucket`),
	regexp.MustCompile(`(?i)BucketNotFound`),
	regexp.MustCompile(`(?i)AccessDenied.*bucket`),
	regexp.MustCompile(`(?i)The specified bucket does not exist`),
	regexp.MustCompile(`(?i)NoSuchKey`),
	regexp.MustCompile(`(?i)AllAccessDisabled`),
}

func (a *URLTechnologyFingerprinter) hasCloudStorage(doc *goquery.Document, lowerBody string, lowerURL string) bool {
	for _, pattern := range cloudStorageURLPatterns {
		if pattern.MatchString(lowerURL) {
			return true
		}
	}

	if lowerBody != "" {
		for _, pattern := range cloudStorageBodyPatterns {
			if pattern.MatchString(lowerBody) {
				return true
			}
		}
	}

	return false
}

// --- Exposed Control Panel Detection ---

var controlPanelURLPatterns = []*regexp.Regexp{
	regexp.MustCompile(`(?i)[/:](?:grafana|prometheus|kibana|elasticsearch)`),
	regexp.MustCompile(`(?i)[/:](?:jenkins|hudson|bamboo|teamcity|drone)`),
	regexp.MustCompile(`(?i)[/:](?:airflow|flower|celery)`),
	regexp.MustCompile(`(?i)[/:](?:rabbitmq|activemq)`),
	regexp.MustCompile(`(?i)[/:](?:sonarqube|sonar)(?:/|$)`),
	regexp.MustCompile(`(?i)[/:](?:portainer|rancher|kubernetes|k8s)`),
	regexp.MustCompile(`(?i)[/:](?:consul|vault|nomad)`),
	regexp.MustCompile(`(?i)[/:](?:traefik|haproxy)(?:/|$)`),
	regexp.MustCompile(`(?i)[/:](?:nagios|zabbix|icinga|cacti|munin|netdata)`),
	regexp.MustCompile(`(?i)[/:](?:gitlab|gitea|gogs)`),
	regexp.MustCompile(`(?i)[/:](?:nexus|artifactory|harbor)`),
	regexp.MustCompile(`(?i)[/:](?:mailhog|roundcube|rainloop)`),
	regexp.MustCompile(`(?i)[/:](?:phpldapadmin|ldapadmin)`),
	regexp.MustCompile(`(?i)[/:](?:pgadmin|phppgadmin)`),
	regexp.MustCompile(`(?i)[/:](?:mongo-express|mongoexpress|rockmongo)`),
	regexp.MustCompile(`(?i)[/:](?:redis-commander|redisinsight)`),
	regexp.MustCompile(`(?i)[/:](?:solr)(?:/|$)`),
	regexp.MustCompile(`(?i)[/:](?:minio)(?:/|$)`),
	regexp.MustCompile(`(?i)[/:](?:cockpit)(?:/|$)`),
	regexp.MustCompile(`(?i)[/:](?:guacamole)(?:/|$)`),
	regexp.MustCompile(`(?i)[/:](?:argo|argocd)(?:/|$)`),
	regexp.MustCompile(`(?i)[/:](?:weave|istio|linkerd)(?:/|$)`),
	regexp.MustCompile(`(?i):\d+/(?:api/v1/|graph|targets|alerts)$`),
}

var controlPanelTitlePatterns = []*regexp.Regexp{
	regexp.MustCompile(`(?i)grafana`),
	regexp.MustCompile(`(?i)kibana`),
	regexp.MustCompile(`(?i)prometheus`),
	regexp.MustCompile(`(?i)jenkins`),
	regexp.MustCompile(`(?i)airflow`),
	regexp.MustCompile(`(?i)rabbitmq\s+management`),
	regexp.MustCompile(`(?i)sonarqube`),
	regexp.MustCompile(`(?i)portainer`),
	// Single dictionary words are contextualised so a title like "The Vault"
	// (a bar) or "Consul général" does not get flagged as a control panel.
	regexp.MustCompile(`(?i)(?:hashicorp\s+)?vault(?:\s+ui|\s+-\s+)`),
	regexp.MustCompile(`(?i)consul\s+(?:by\s+hashicorp|ui)`),
	regexp.MustCompile(`(?i)traefik`),
	regexp.MustCompile(`(?i)nagios`),
	regexp.MustCompile(`(?i)zabbix`),
	regexp.MustCompile(`(?i)nexus\s+repository`),
	regexp.MustCompile(`(?i)pgadmin`),
	regexp.MustCompile(`(?i)mongo\s*express`),
	regexp.MustCompile(`(?i)redis\s*commander`),
	regexp.MustCompile(`(?i)(?:celery\s+)?flower`),
	regexp.MustCompile(`(?i)argo\s*cd`),
	regexp.MustCompile(`(?i)rancher`),
	regexp.MustCompile(`(?i)gitea`),
	regexp.MustCompile(`(?i)gitlab`),
	regexp.MustCompile(`(?i)harbor\s+(?:registry|-)`),
	regexp.MustCompile(`(?i)netdata`),
	regexp.MustCompile(`(?i)cockpit\s+-\s+`),
	regexp.MustCompile(`(?i)solr\s+admin`),
	regexp.MustCompile(`(?i)minio\s+(?:console|browser)`),
	regexp.MustCompile(`(?i)guacamole`),
	regexp.MustCompile(`(?i)elasticsearch`),
}

var controlPanelBodyPatterns = []*regexp.Regexp{
	regexp.MustCompile(`(?i)grafana-app`),
	regexp.MustCompile(`(?i)kibana-body`),
	regexp.MustCompile(`(?i)jenkins-head`),
	regexp.MustCompile(`(?i)id\s*=\s*["']jenkins["']`),
	regexp.MustCompile(`(?i)rabbit.*management`),
	regexp.MustCompile(`(?i)sonarqube`),
	regexp.MustCompile(`(?i)portainer`),
	regexp.MustCompile(`(?i)prometheus.*time.*series`),
	regexp.MustCompile(`(?i)consul.*service.*mesh`),
	regexp.MustCompile(`(?i)hashicorp.*vault`),
	regexp.MustCompile(`(?i)airflow.*dag`),
}

func (a *URLTechnologyFingerprinter) hasControlPanel(doc *goquery.Document, lowerBody string, lowerURL string) bool {
	for _, pattern := range controlPanelURLPatterns {
		if pattern.MatchString(lowerURL) {
			return true
		}
	}

	if doc != nil {
		title := doc.Find("title").Text()
		for _, pattern := range controlPanelTitlePatterns {
			if pattern.MatchString(title) {
				return true
			}
		}
	}

	if lowerBody != "" {
		for _, pattern := range controlPanelBodyPatterns {
			if pattern.MatchString(lowerBody) {
				return true
			}
		}
	}

	return false
}

// --- Payment / Checkout Page Detection ---

var paymentURLPatterns = []*regexp.Regexp{
	regexp.MustCompile(`(?i)[/\?#&]checkout(?:[/\?#&]|$)`),
	regexp.MustCompile(`(?i)[/\?#&]payment(?:s)?(?:[/\?#&]|$)`),
	regexp.MustCompile(`(?i)[/\?#&]billing(?:[/\?#&]|$)`),
	regexp.MustCompile(`(?i)[/\?#&]paiement`),
	regexp.MustCompile(`(?i)[/\?#&]pay(?:[/\?#&]|$)`),
	regexp.MustCompile(`(?i)[/\?#&](?:sub|subscribe|subscription|abonnement)(?:[/\?#&]|$)`),
	regexp.MustCompile(`(?i)[/\?#&]cart(?:[/\?#&]|$)`),
	regexp.MustCompile(`(?i)[/\?#&]panier`),
	regexp.MustCompile(`(?i)[/\?#&]order[_-]?(?:confirm|review|summary)`),
}

var paymentBodyPatterns = []*regexp.Regexp{
	// Payment provider SDKs / iframes
	regexp.MustCompile(`(?i)js\.stripe\.com`),
	regexp.MustCompile(`(?i)checkout\.stripe\.com`),
	regexp.MustCompile(`(?i)Stripe\s*\(`),
	regexp.MustCompile(`(?i)paypal(?:objects|\.com/sdk)`),
	regexp.MustCompile(`(?i)braintreegateway\.com`),
	regexp.MustCompile(`(?i)js\.braintreegateway`),
	regexp.MustCompile(`(?i)checkout\.razorpay\.com`),
	regexp.MustCompile(`(?i)adyen(?:\.com|checkout)`),
	regexp.MustCompile(`(?i)squareup\.com`),
	regexp.MustCompile(`(?i)checkout\.com`),
	regexp.MustCompile(`(?i)mollie\.com`),
	// Card input fields
	regexp.MustCompile(`(?i)name\s*=\s*["'](?:card[_-]?number|cardnumber|cc[_-]?number|cvv|cvc|card[_-]?cvc)["']`),
	regexp.MustCompile(`(?i)autocomplete\s*=\s*["']cc-(?:number|exp|csc)["']`),
	regexp.MustCompile(`(?i)id\s*=\s*["'](?:card-element|card-number|payment-form)["']`),
}

var paymentTitleKeywords = []string{
	"checkout", "payment", "billing", "paiement",
	"subscribe", "subscription", "abonnement",
	"your cart", "shopping cart", "panier",
}

func (a *URLTechnologyFingerprinter) hasPaymentPage(doc *goquery.Document, lowerBody string, lowerURL string) bool {
	if matchAnyPattern(paymentURLPatterns, lowerURL) {
		return true
	}
	if lowerBody != "" && matchAnyPattern(paymentBodyPatterns, lowerBody) {
		return true
	}
	if doc != nil {
		title := strings.ToLower(doc.Find("title").Text())
		if containsAny(title, paymentTitleKeywords) {
			return true
		}
	}
	return false
}

// --- Open Redirect Parameter Detection ---
// Flags URLs whose query carries a redirect-style parameter pointing at an
// absolute URL or protocol-relative target — a classic open-redirect and
// SSRF entry point worth manual review. Tagged as danger.

var openRedirectParamPattern = regexp.MustCompile(`(?i)[?&](?:redirect(?:_uri|_url|to)?|redir|return(?:_?url|to|_path)?|next|url|dest(?:ination)?|continue|goto|callback|forward|out|target|rurl|link|u|to)=([^&]+)`)

func (a *URLTechnologyFingerprinter) hasOpenRedirectParam(rawURL string) bool {
	matches := openRedirectParamPattern.FindAllStringSubmatch(rawURL, -1)
	for _, m := range matches {
		if len(m) < 2 {
			continue
		}
		value := strings.ToLower(m[1])
		// Absolute URL, protocol-relative //host, or an encoded variant.
		if strings.HasPrefix(value, "http%3a") || strings.HasPrefix(value, "https%3a") ||
			strings.HasPrefix(value, "http://") || strings.HasPrefix(value, "https://") ||
			strings.HasPrefix(value, "//") || strings.HasPrefix(value, "%2f%2f") {
			return true
		}
	}
	return false
}

// --- CAPTCHA Detection ---
// Records whether a form/page is protected by a CAPTCHA. Useful context when
// triaging login and signup surfaces at scale.

var captchaBodyPatterns = []*regexp.Regexp{
	regexp.MustCompile(`(?i)www\.google\.com/recaptcha`),
	regexp.MustCompile(`(?i)g-recaptcha`),
	regexp.MustCompile(`(?i)grecaptcha`),
	regexp.MustCompile(`(?i)hcaptcha\.com`),
	regexp.MustCompile(`(?i)\bh-captcha\b`),
	regexp.MustCompile(`(?i)challenges\.cloudflare\.com/turnstile`),
	regexp.MustCompile(`(?i)cf-turnstile`),
	regexp.MustCompile(`(?i)funcaptcha|arkoselabs`),
}

func (a *URLTechnologyFingerprinter) hasCaptcha(lowerBody string) bool {
	if lowerBody == "" {
		return false
	}
	return matchAnyPattern(captchaBodyPatterns, lowerBody)
}

// --- 404 Page Classification ---
// Distinguishes between empty/default 404s and 404s with rich content
// (app behind it, custom error page with JS framework, etc.)

// Patterns for generic/default 404 pages served by web servers
var default404BodyPatterns = []*regexp.Regexp{
	// Apache / Nginx / IIS default error pages
	regexp.MustCompile(`(?i)<title>\s*404\s+not\s+found\s*</title>`),
	regexp.MustCompile(`(?i)<h1>\s*not\s+found\s*</h1>`),
	regexp.MustCompile(`(?i)<h1>\s*404\s+not\s+found\s*</h1>`),
	regexp.MustCompile(`(?i)the requested url was not found on this server`),
	regexp.MustCompile(`(?i)the page you requested was not found`),
	regexp.MustCompile(`(?i)the resource requested could not be found`),
	regexp.MustCompile(`(?i)404 - file or directory not found`),
	regexp.MustCompile(`(?i)server at .* port \d+`),
	regexp.MustCompile(`(?i)<address>apache`),
	regexp.MustCompile(`(?i)<address>nginx`),
	regexp.MustCompile(`(?i)<hr><center>nginx</center>`),
	regexp.MustCompile(`(?i)microsoft-iis/\d`),
	// Cloudflare / CDN default
	regexp.MustCompile(`(?i)error 404.*cloudflare`),
	// Generic
	regexp.MustCompile(`(?i)^not found$`),
	regexp.MustCompile(`(?i)<body>\s*<h1>404</h1>\s*</body>`),
	// French
	regexp.MustCompile(`(?i)page\s+non\s+trouv[eé]e`),
	regexp.MustCompile(`(?i)la\s+page\s+demand[eé]e\s+n'existe\s+pas`),
}

// Indicators that a 404 page has real application content behind it
var richContent404Patterns = []*regexp.Regexp{
	// JS frameworks / bundles
	regexp.MustCompile(`(?i)<script[^>]*src\s*=\s*["'][^"']*(?:bundle|chunk|app|main|vendor|runtime|webpack|polyfill)[^"']*\.js`),
	regexp.MustCompile(`(?i)__NEXT_DATA__`),
	regexp.MustCompile(`(?i)__NUXT__`),
	regexp.MustCompile(`(?i)window\.__INITIAL_STATE__`),
	regexp.MustCompile(`(?i)window\.__PRELOADED_STATE__`),
	regexp.MustCompile(`(?i)data-reactroot`),
	regexp.MustCompile(`(?i)data-react-helmet`),
	regexp.MustCompile(`(?i)ng-app\s*=`),
	regexp.MustCompile(`(?i)ng-controller\s*=`),
	regexp.MustCompile(`(?i)<div\s[^>]*id\s*=\s*["'](?:app|root|__next|__nuxt)["']`),
	// Stylesheets / CSS frameworks (indicates custom design)
	regexp.MustCompile(`(?i)<link[^>]*rel\s*=\s*["']stylesheet["'][^>]*href\s*=\s*["'][^"']*(?:app|main|style|chunk)[^"']*\.css`),
	// Custom navigation / layout
	regexp.MustCompile(`(?i)<(?:nav|header|footer|aside)\b`),
	// Service worker / PWA
	regexp.MustCompile(`(?i)serviceWorker`),
	regexp.MustCompile(`(?i)<link[^>]*rel\s*=\s*["']manifest["']`),
	// API calls / AJAX
	regexp.MustCompile(`(?i)fetch\s*\(`),
	regexp.MustCompile(`(?i)XMLHttpRequest`),
	regexp.MustCompile(`(?i)axios`),
	// Authentication / session indicators
	regexp.MustCompile(`(?i)csrf[_-]?token`),
	regexp.MustCompile(`(?i)authenticity[_-]?token`),
}

func (a *URLTechnologyFingerprinter) classify404(page *core.Page, doc *goquery.Document, lowerBody string) {
	// Only process pages with 404 status
	if !strings.Contains(page.Status, "404") {
		return
	}

	// Case 1: No body at all → empty 404
	if lowerBody == "" {
		page.AddTag("404 - Empty", "feature", "")
		a.session.Out.Debug("[%s] Detected empty 404 on %s\n", a.ID(), page.URL)
		return
	}

	bodyLen := len(strings.TrimSpace(lowerBody))

	// Case 2: Very short body (< 512 bytes) → likely a default server response
	if bodyLen < 512 {
		page.AddTag("404 - Empty", "feature", "")
		a.session.Out.Debug("[%s] Detected minimal 404 on %s (body: %d bytes)\n", a.ID(), page.URL, bodyLen)
		return
	}

	// Case 3: Matches default server 404 page patterns
	isDefault := false
	for _, pattern := range default404BodyPatterns {
		if pattern.MatchString(lowerBody) {
			isDefault = true
			break
		}
	}

	// Check for rich content indicators
	hasRichContent := false

	// Check regex patterns
	for _, pattern := range richContent404Patterns {
		if pattern.MatchString(lowerBody) {
			hasRichContent = true
			break
		}
	}

	// Check DOM structure if available
	if !hasRichContent && doc != nil {
		// Multiple script tags with src = bundled app
		scriptCount := doc.Find("script[src]").Length()
		if scriptCount >= 3 {
			hasRichContent = true
		}

		// Module scripts = modern SPA
		if doc.Find("script[type='module']").Length() > 0 {
			hasRichContent = true
		}

		// Significant DOM depth/structure (nav, header, footer, aside)
		structuralElements := doc.Find("nav, header, footer, aside, main").Length()
		if structuralElements >= 2 {
			hasRichContent = true
		}

		// Many div elements = real app layout
		divCount := doc.Find("div").Length()
		if divCount >= 10 {
			hasRichContent = true
		}
	}

	// Large body with no default patterns = likely custom content
	if !hasRichContent && !isDefault && bodyLen > 2048 {
		hasRichContent = true
	}

	if hasRichContent {
		page.AddTag("404 - Rich Content", "danger", "")
		a.session.Out.Debug("[%s] Detected rich 404 on %s (body: %d bytes) — app likely behind\n", a.ID(), page.URL, bodyLen)
	} else {
		page.AddTag("404 - Empty", "feature", "")
		a.session.Out.Debug("[%s] Detected default 404 on %s\n", a.ID(), page.URL)
	}
}
