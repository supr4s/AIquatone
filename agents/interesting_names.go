package agents

import (
	"strings"
	"unicode"

	"github.com/PuerkitoBio/goquery"
)

// --- Interesting Title Detection ---
//
// Bug-bounty style triage signal: a page whose <title> carries a word such as
// "admin", "dev", "preprod", "intranet" or "jenkins" is worth a manual look
// even when no other feature fired. Every matched keyword becomes a tag of
// type "interesting" so the report's Interesting Titles tab can group pages
// by keyword. Matching is on whole words only, Unicode-aware, so "test" does
// not match "détest" and "dev" does not match "devices".

var interestingTitleKeywords = []string{
	// Environments
	"dev", "development", "developer", "developers", "devel",
	"staging", "preprod", "pre-prod", "preproduction", "pre-production", "préprod", "pré-prod",
	"uat", "qa", "test", "testing", "tests", "sandbox", "sbx", "demo", "beta", "poc", "pilot",
	"recette", "développement", "bac à sable",
	// Access scope
	"internal", "intranet", "private", "interne", "restricted", "confidential", "confidentiel",
	"localhost", "127.0.0.1",
	// Administration
	"admin", "administrator", "administration", "backoffice", "back office", "back-office",
	"dashboard", "control panel", "console", "tableau de bord", "espace admin",
	"cpanel", "plesk", "webmin", "directadmin", "ispconfig",
	"phpmyadmin", "adminer", "pgadmin", "phppgadmin",
	// Debug / diagnostics / defaults
	"debug", "phpinfo", "monitoring", "logs", "config", "configuration", "setup", "installer",
	"maintenance", "under construction", "en construction", "en maintenance",
	"index of", "directory listing", "hello world", "lorem ipsum", "untitled", "test page",
	"just another wordpress site",
	// APIs
	"api", "apis", "swagger", "swagger ui", "openapi", "graphql", "graphiql", "redoc", "api docs", "api documentation",
	// DevOps / infrastructure tooling
	"jenkins", "gitlab", "gitea", "gogs", "bitbucket", "jira", "confluence", "sonarqube", "nexus repository",
	"artifactory", "grafana", "kibana", "prometheus", "zabbix", "nagios", "portainer", "rancher",
	"kubernetes", "openshift", "argo cd", "argocd", "airflow", "rabbitmq", "keycloak", "minio",
	"elasticsearch", "mysql", "mariadb", "postgres", "postgresql", "mongodb", "redis", "database", "sql",
	// Remote access / mail
	"vpn", "sslvpn", "openvpn", "globalprotect", "pulse secure", "fortigate", "citrix", "remote desktop", "rdweb",
	"webmail", "roundcube", "zimbra", "outlook web", "owa", "horde", "squirrelmail",
	// Devices / out-of-band management
	"router", "printer", "ilo", "idrac", "ipmi", "ip camera", "network camera", "dvr", "nvr",
	// Files
	"upload", "file manager", "backup", "backups", "legacy", "old", "temp", "tmp", "wip", "todo",
}

// normalizeWords lower-cases text and collapses every run of non-letter,
// non-digit characters into a single space, surrounded by spaces so that a
// " keyword " substring search is a whole-word match. "Pre-Prod (Admin)"
// becomes " pre prod admin ".
func normalizeWords(text string) string {
	var b strings.Builder
	b.WriteByte(' ')
	lastSpace := true
	for _, r := range strings.ToLower(text) {
		if unicode.IsLetter(r) || unicode.IsNumber(r) {
			b.WriteRune(r)
			lastSpace = false
		} else if !lastSpace {
			b.WriteByte(' ')
			lastSpace = true
		}
	}
	if !lastSpace {
		b.WriteByte(' ')
	}
	return b.String()
}

var normalizedTitleKeywords = func() []string {
	out := make([]string, 0, len(interestingTitleKeywords))
	for _, kw := range interestingTitleKeywords {
		out = append(out, strings.TrimSpace(normalizeWords(kw)))
	}
	return out
}()

// findInterestingTitleKeywords returns every juicy keyword found in the page
// title, in keyword-list order, or nil. The <title> from the parsed body is
// preferred because the title extractor agent runs concurrently and may not
// have populated page.PageTitle yet.
func findInterestingTitleKeywords(pageTitle string, doc *goquery.Document) []string {
	title := ""
	if doc != nil {
		title = doc.Find("title").First().Text()
	}
	if strings.TrimSpace(title) == "" {
		title = pageTitle
	}
	normalized := normalizeWords(title)
	if strings.TrimSpace(normalized) == "" {
		return nil
	}

	var found []string
	seen := map[string]bool{}
	for i, kw := range normalizedTitleKeywords {
		if seen[kw] {
			continue
		}
		if strings.Contains(normalized, " "+kw+" ") {
			seen[kw] = true
			found = append(found, strings.ToLower(interestingTitleKeywords[i]))
		}
	}
	return found
}
