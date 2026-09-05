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
