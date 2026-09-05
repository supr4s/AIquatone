package agents

import (
	"strings"
	"testing"

	"github.com/PuerkitoBio/goquery"
)

func detectAuthForTest(t *testing.T, rawURL string, html string) authFeatureResult {
	t.Helper()
	doc, err := goquery.NewDocumentFromReader(strings.NewReader(html))
	if err != nil {
		t.Fatalf("failed to parse test HTML: %v", err)
	}
	fingerprinter := &URLTechnologyFingerprinter{}
	return fingerprinter.detectAuthFeatures(doc, strings.ToLower(html), strings.ToLower(rawURL))
}

func TestDetectAuthFeaturesLoginForm(t *testing.T) {
	result := detectAuthForTest(t, "https://app.example.com/login", `
		<html>
			<head><title>Sign in</title></head>
			<body>
				<form action="/login">
					<input type="email" name="email">
					<input type="password" name="password">
					<button type="submit">Sign in</button>
				</form>
			</body>
		</html>
	`)

	if !result.LoginPage {
		t.Fatalf("expected LoginPage=true, score=%d", result.LoginScore)
	}
	if result.SignupPage {
		t.Fatalf("expected SignupPage=false, score=%d", result.SignupScore)
	}
}

func TestDetectAuthFeaturesLoginLinkOnly(t *testing.T) {
	result := detectAuthForTest(t, "https://www.example.com/", `
		<html>
			<head><title>Product</title></head>
			<body>
				<a href="/login">Sign in</a>
				<a href="/pricing">Pricing</a>
			</body>
		</html>
	`)

	if result.LoginPage {
		t.Fatalf("expected LoginPage=false for link-only page, score=%d", result.LoginScore)
	}
	if !result.LoginLink {
		t.Fatalf("expected LoginLink=true, score=%d", result.LoginScore)
	}
}

func TestDetectAuthFeaturesPasswordResetIsNotLoginOrSignup(t *testing.T) {
	result := detectAuthForTest(t, "https://app.example.com/reset-password", `
		<html>
			<head><title>Reset Password</title></head>
			<body>
				<form action="/reset-password">
					<input type="password" name="new_password">
					<input type="password" name="confirm_password">
					<button type="submit">Reset password</button>
				</form>
			</body>
		</html>
	`)

	if result.LoginPage || result.LoginLink {
		t.Fatalf("expected no login classification for reset page, login score=%d", result.LoginScore)
	}
	if result.SignupPage || result.SignupLink {
		t.Fatalf("expected no signup classification for reset page, signup score=%d", result.SignupScore)
	}
}

func TestDetectAuthFeaturesSignupForm(t *testing.T) {
	result := detectAuthForTest(t, "https://app.example.com/register", `
		<html>
			<head><title>Create account</title></head>
			<body>
				<form action="/register">
					<input type="email" name="email">
					<input type="password" name="password">
					<input type="password" name="confirm_password">
					<button type="submit">Create account</button>
				</form>
			</body>
		</html>
	`)

	if !result.SignupPage {
		t.Fatalf("expected SignupPage=true, score=%d", result.SignupScore)
	}
	if result.LoginPage {
		t.Fatalf("expected LoginPage=false for signup form, score=%d", result.LoginScore)
	}
}

func TestDetectAuthFeaturesSSOProvider(t *testing.T) {
	result := detectAuthForTest(t, "https://app.example.com/login", `
		<html>
			<head><title>Corporate login</title></head>
			<body>
				<div id="okta-sign-in"></div>
				<script src="https://example.okta.com/js/okta-signin-widget.js"></script>
			</body>
		</html>
	`)

	if !result.LoginPage {
		t.Fatalf("expected LoginPage=true for SSO login, score=%d", result.LoginScore)
	}
	if !result.SSO {
		t.Fatal("expected SSO=true")
	}
	if result.SSOProvider != "Okta" {
		t.Fatalf("expected SSOProvider=Okta, got %q", result.SSOProvider)
	}
}

func TestTechnologyNamesPreservesVersion(t *testing.T) {
	baseName, displayName := technologyNames("Apache HTTP Server:2.4.62")
	if baseName != "Apache HTTP Server" {
		t.Fatalf("expected base name to be preserved, got %q", baseName)
	}
	if displayName != "Apache HTTP Server 2.4.62" {
		t.Fatalf("expected display name with version, got %q", displayName)
	}
}

func TestFeatureDetectorsForPreviouslyUnwiredFeatures(t *testing.T) {
	fingerprinter := &URLTechnologyFingerprinter{}
	body := `<form enctype="multipart/form-data"><input type="file" name="artifact"></form>`
	doc, err := goquery.NewDocumentFromReader(strings.NewReader(body))
	if err != nil {
		t.Fatalf("failed to parse test HTML: %v", err)
	}

	if !fingerprinter.hasFileUpload(doc, strings.ToLower(body)) {
		t.Fatal("expected file upload detection")
	}
	if !fingerprinter.hasSensitiveExposure(nil, "", "https://example.com/.env") {
		t.Fatal("expected sensitive exposure detection")
	}
}

func TestSignupFormDoesNotProduceLoginLink(t *testing.T) {
	result := detectAuthForTest(t, "https://app.example.com/register", `
		<html>
			<head><title>Create account</title></head>
			<body>
				<form action="/register">
					<input type="email" name="email">
					<input type="password" name="password">
					<input type="password" name="confirm_password">
					<button type="submit">Create account</button>
				</form>
			</body>
		</html>
	`)

	if result.LoginLink {
		t.Fatalf("signup form must not be tagged as Login Link (login=%d signup=%d)", result.LoginScore, result.SignupScore)
	}
	if !result.SignupPage {
		t.Fatalf("expected SignupPage=true, score=%d", result.SignupScore)
	}
}

func TestHasOpenRedirectParam(t *testing.T) {
	f := &URLTechnologyFingerprinter{}
	positives := []string{
		"https://x.example.com/go?redirect=https://evil.com",
		"https://x.example.com/login?next=//evil.com/x",
		"https://x.example.com/o?url=http%3a%2f%2fevil.com",
		"https://x.example.com/r?returnTo=https://evil.com",
	}
	for _, u := range positives {
		if !f.hasOpenRedirectParam(u) {
			t.Errorf("expected open-redirect detection for %q", u)
		}
	}
	negatives := []string{
		"https://x.example.com/go?redirect=/dashboard",
		"https://x.example.com/search?q=url",
		"https://x.example.com/page?next=2",
		"https://x.example.com/",
	}
	for _, u := range negatives {
		if f.hasOpenRedirectParam(u) {
			t.Errorf("did not expect open-redirect detection for %q", u)
		}
	}
}

func TestHasPaymentPage(t *testing.T) {
	f := &URLTechnologyFingerprinter{}
	if !f.hasPaymentPage(nil, "", "https://shop.example.com/checkout") {
		t.Error("expected payment detection from /checkout URL")
	}
	body := `<html><body><script src="https://js.stripe.com/v3/"></script><div id="card-element"></div></body></html>`
	if !f.hasPaymentPage(nil, strings.ToLower(body), "https://shop.example.com/") {
		t.Error("expected payment detection from Stripe SDK")
	}
	if f.hasPaymentPage(nil, "hello world", "https://blog.example.com/article") {
		t.Error("did not expect payment detection on a plain article")
	}
}

func TestHasCaptcha(t *testing.T) {
	f := &URLTechnologyFingerprinter{}
	if !f.hasCaptcha(strings.ToLower(`<div class="g-recaptcha" data-sitekey="x"></div>`)) {
		t.Error("expected reCAPTCHA detection")
	}
	if f.hasCaptcha("no captcha here") {
		t.Error("did not expect CAPTCHA detection")
	}
}

func TestMinioNotMatchedInDominio(t *testing.T) {
	f := &URLTechnologyFingerprinter{}
	if f.hasCloudStorage(nil, "", "https://www.example.com/mi-dominio/inicio") {
		t.Error("minio pattern must not match the substring in 'dominio'")
	}
	if !f.hasCloudStorage(nil, "", "https://minio.example.com/bucket") {
		t.Error("expected minio host detection")
	}
}

func parseDocForTest(t *testing.T, html string) *goquery.Document {
	t.Helper()
	doc, err := goquery.NewDocumentFromReader(strings.NewReader(html))
	if err != nil {
		t.Fatalf("failed to parse test HTML: %v", err)
	}
	return doc
}

func TestAdminPageIgnoresSubstringsAndLongHeadings(t *testing.T) {
	f := &URLTechnologyFingerprinter{}
	falsePositives := map[string]string{
		"romanian verb":    `<html><head><title>Afaceri smart</title></head><body><h3 class="footer-title">Administrezi un spatiu commercial</h3></body></html>`,
		"article card":     `<html><head><title>Orange Newsroom</title></head><body><h2 class="m-article-card__title">Top management changes announced for the next fiscal year</h2></body></html>`,
		"badminton":        `<html><head><title>Badminton club</title></head><body></body></html>`,
		"suggestion":       `<html><head><title>Suggestion box</title></head><body></body></html>`,
		"password manager": `<html><head><title>Best password manager</title></head><body></body></html>`,
	}
	for name, html := range falsePositives {
		if f.hasAdminPage(parseDocForTest(t, html), strings.ToLower(html), "https://example.com/") {
			t.Errorf("%s: expected no Admin Page", name)
		}
	}

	truePositives := map[string]string{
		"title":   `<html><head><title>Admin - MyApp</title></head><body></body></html>`,
		"heading": `<html><head><title>MyApp</title></head><body><h1>Administration</h1></body></html>`,
		"french":  `<html><head><title>Tableau de bord</title></head><body></body></html>`,
	}
	for name, html := range truePositives {
		if !f.hasAdminPage(parseDocForTest(t, html), strings.ToLower(html), "https://example.com/") {
			t.Errorf("%s: expected Admin Page", name)
		}
	}
	if !f.hasAdminPage(nil, "", "https://example.com/admin/") {
		t.Errorf("url: expected Admin Page")
	}
}

func TestSensitiveExposureIgnoresPublicAPIKeys(t *testing.T) {
	f := &URLTechnologyFingerprinter{}
	body := `<script>const ghostSearchApiKey = '8f6024127a20112c41b734c513'; var api_key = "AIza..."; </script>`
	if f.hasSensitiveExposure(nil, strings.ToLower(body), "https://example.com/") {
		t.Fatalf("public api keys must not trigger Sensitive Exposure")
	}
	body = `<pre>AWS_SECRET_ACCESS_KEY=abc\nsecret_key: hunter2</pre>`
	if !f.hasSensitiveExposure(nil, strings.ToLower(body), "https://example.com/") {
		t.Fatalf("expected Sensitive Exposure for secret_key")
	}
}

func TestMFAIgnoresPasskeyAutofillHint(t *testing.T) {
	if hasMFA(`<input autocomplete="username webauthn" name="identifier">`, "sign in") {
		t.Fatalf("passkey autofill hint alone must not be MFA")
	}
	if !hasMFA(`<p>Enter the verification code from your authenticator app</p>`, "") {
		t.Fatalf("expected MFA")
	}
}

func TestSSOProviderGoogleBeforeSAML(t *testing.T) {
	body := `<html><body><form action="https://accounts.google.com/signin"></form><script>["relaystate","samlrequest","sigalg"]</script></body></html>`
	got := detectSSOProvider("https://dashboard-dev.example.com/", strings.ToLower(body), parseDocForTest(t, body))
	if got != "Google" {
		t.Fatalf("expected Google, got %q", got)
	}
	if got := detectSSOProvider("https://sso.example.com/saml/sso?SAMLRequest=abc", "", nil); got != "SAML" {
		t.Fatalf("expected SAML, got %q", got)
	}
	if got := detectSSOProvider("https://app.example.com/oauth/authorize?client_id=1", "", nil); got != "" {
		t.Fatalf("generic /authorize must not be attributed to Auth0, got %q", got)
	}
}

func TestInterestingTitleKeyword(t *testing.T) {
	cases := map[string]string{
		"Admin - MyApp":                        "admin",
		"MyApp (preprod)":                      "preprod",
		"Jenkins [Jenkins]":                    "jenkins",
		"Index of /backup":                     "index of",
		"Tableau de bord":                      "tableau de bord",
		"Dashboard DEV":                        "dashboard",
		"Orange 5G Lab":                        "",
		"Sign in - Google Accounts":            "",
		"Speedtest by Ookla":                   "",
		"Nos offres de stage et développement": "développement",
		"Je déteste les lundis":                "",
		"Contest results":                      "",
		"Devices and accessories":              "",
	}
	for title, want := range cases {
		if got := interestingTitleKeyword(title, nil); got != want {
			t.Errorf("%q: got %q, want %q", title, got, want)
		}
	}
	doc := parseDocForTest(t, `<html><head><title>  Staging &ndash; Shop </title></head></html>`)
	if got := interestingTitleKeyword("", doc); got != "staging" {
		t.Errorf("doc title: got %q", got)
	}
}

func TestInterestingHostnameKeyword(t *testing.T) {
	cases := map[string]string{
		"https://temperature-dashboard-dev.orange.ro/": "dashboard",
		"https://ndt-sbx.example.com/":                 "sbx",
		"https://nbe-ppr.example.com/":                 "ppr",
		"http://testaes.example.com:8080/":             "test",
		"https://dev01.example.co.uk/":                 "dev",
		"https://my-admin.example.com/":                "admin",
		"https://contest.example.com/":                 "",
		"https://devices.example.com/":                 "",
		"https://www.example.com/":                     "",
		"https://example.com/admin":                    "",
		"https://test.com/":                            "",
		"http://10.0.0.1:8080/":                        "",
		"https://newsroom.example.com/":                "",
		"https://content-ci360.example.com/":           "",
		"https://ci.example.com/":                      "ci",
		"https://uat2.example.com/":                    "uat",
	}
	for raw, want := range cases {
		if got := interestingHostnameKeyword(raw); got != want {
			t.Errorf("%s: got %q, want %q", raw, got, want)
		}
	}
}
