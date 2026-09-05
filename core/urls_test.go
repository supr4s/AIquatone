package core

import (
	"strings"
	"testing"
)

func TestBaseFilenameIncludesQueryString(t *testing.T) {
	first := BaseFilenameFromURL("https://example.com/search?q=first")
	second := BaseFilenameFromURL("https://example.com/search?q=second")
	if first == second {
		t.Fatalf("expected distinct filenames for distinct query strings, got %q", first)
	}
}

func TestBaseFilenameIsFilesystemSafeForIPv6(t *testing.T) {
	filename := BaseFilenameFromURL("https://[2001:db8::1]:8443/status")
	if strings.ContainsAny(filename, ":[]") {
		t.Fatalf("expected filesystem-safe filename, got %q", filename)
	}
}

func TestPageUsesCanonicalBaseFilename(t *testing.T) {
	page, err := NewPage("https://example.com/path?mode=full#summary")
	if err != nil {
		t.Fatalf("failed to create page: %v", err)
	}
	if page.BaseFilename() != BaseFilenameFromURL(page.URL) {
		t.Fatalf("page filename %q differs from canonical filename %q", page.BaseFilename(), BaseFilenameFromURL(page.URL))
	}
}
