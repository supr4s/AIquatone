package agents

import (
	"net/url"
	"regexp"
	"strings"

	"github.com/PuerkitoBio/goquery"
)

// --- Interesting Title / Hostname Detection ---
//
// Bug-bounty style triage signals: a page whose <title> or hostname carries a
// word such as "admin", "dev", "preprod" or "jenkins" is worth a manual look
// even when no other feature fired. Titles are matched on whole words only,
// hostnames on individual labels (split on ".", "-" and "_").

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

// Exact hostname label tokens (after splitting on "-" and "_" and stripping up
// to two trailing digits, so "dev01" and "ppr-2" match too).
var interestingHostnameTokens = []string{
	// Environments
	"dev", "devel", "develop", "development", "developer", "developers",
	"staging", "stg", "stag", "preprod", "pprod", "ppr", "prp", "prep", "preproduction",
	"uat", "qa", "test", "tst", "testing", "sandbox", "sbx", "demo", "beta", "alpha", "canary", "preview",
	"lab", "labs", "poc", "pilot", "recette", "rec",
	// Access scope
	"int", "internal", "intra", "intranet", "corp", "corporate", "priv", "private", "dmz",
	// Administration
	"admin", "adm", "administrator", "backoffice", "console", "panel", "cpanel", "plesk", "webmin",
	"dashboard", "portal", "cms", "manage", "management", "mgmt",
	// Ops / monitoring
	"ops", "devops", "sre", "infra", "tools", "tool", "utils", "monitor", "monitoring", "mon", "metrics",
	"debug", "logs", "log", "syslog", "splunk", "graylog", "elk", "elastic", "kibana", "grafana", "prometheus",
	"zabbix", "nagios",
	// CI / code / artifacts
	"ci", "build", "jenkins", "gitlab", "git", "svn", "jira", "confluence", "wiki", "sonar", "sonarqube",
	"nexus", "artifactory", "registry", "docker", "harbor", "k8s", "kube", "kubernetes", "rancher",
	"portainer", "vault", "consul", "argocd", "airflow",
	// Remote access / mail
	"vpn", "sslvpn", "remote", "citrix", "rdp", "rds", "owa", "webmail", "mail", "exchange",
	// Files / data
	"ftp", "sftp", "files", "upload", "uploads", "share", "nas", "backup", "backups", "bak",
	"old", "legacy", "archive", "tmp", "temp", "new",
	"db", "database", "mysql", "mariadb", "postgres", "pgsql", "mongo", "mongodb", "redis", "sql",
	"phpmyadmin", "pma", "adminer",
	// APIs / auth
	"api", "apis", "rest", "graphql", "soap", "swagger", "v1", "v2",
	"sso", "auth", "login", "oauth", "idp", "ldap", "iam", "keycloak",
}

// Strong keywords also matched as a prefix or suffix of a whole label, so
// "testaes", "devportal" or "myadmin" are caught.
var interestingHostnameAffixes = []string{"test", "admin", "staging", "preprod", "sandbox", "uat"}

// Labels that contain an affix keyword but are ordinary words.
var interestingHostnameAffixStoplist = map[string]bool{
	"contest": true, "contests": true, "latest": true, "greatest": true, "fastest": true,
	"protest": true, "attest": true, "attestation": true, "testimonial": true, "testimonials": true,
}

// Second-level labels under which the registrable domain has three labels
// (example.co.uk, example.com.au).
var secondLevelDomainLabels = map[string]bool{
	"co": true, "com": true, "org": true, "net": true, "gov": true, "edu": true, "ac": true, "gouv": true,
}

var interestingTitlePattern = buildKeywordPattern(interestingTitleKeywords)

// At most two trailing digits are stripped ("dev01", "uat2"); longer digit
// runs are product names ("ci360", "sap4000"), not environment counters.
var trailingDigitsPattern = regexp.MustCompile(`\d{1,2}$`)

// buildKeywordPattern compiles a case-insensitive, word-bounded alternation
// of the given keywords. Longest keywords first so "pre-prod" wins over "pre".
func buildKeywordPattern(keywords []string) *regexp.Regexp {
	sorted := append([]string(nil), keywords...)
	for i := 1; i < len(sorted); i++ {
		for j := i; j > 0 && len(sorted[j]) > len(sorted[j-1]); j-- {
			sorted[j], sorted[j-1] = sorted[j-1], sorted[j]
		}
	}
	quoted := make([]string, 0, len(sorted))
	for _, kw := range sorted {
		quoted = append(quoted, regexp.QuoteMeta(kw))
	}
	// Unicode-aware boundaries: \b only knows ASCII word characters, which
	// would let "test" match inside "détest". Use explicit non-letter guards.
	return regexp.MustCompile(`(?i)(?:^|[^\p{L}\p{N}])(` + strings.Join(quoted, "|") + `)(?:$|[^\p{L}\p{N}])`)
}

// interestingTitleKeyword returns the first juicy keyword found in the page
// title, or "" when there is none. The <title> from the parsed body is
// preferred because the title extractor agent runs concurrently and may not
// have populated page.PageTitle yet.
func interestingTitleKeyword(pageTitle string, doc *goquery.Document) string {
	title := ""
	if doc != nil {
		title = doc.Find("title").First().Text()
	}
	if strings.TrimSpace(title) == "" {
		title = pageTitle
	}
	title = strings.Join(strings.Fields(title), " ")
	if title == "" {
		return ""
	}
	if m := interestingTitlePattern.FindStringSubmatch(title); m != nil {
		return strings.ToLower(m[1])
	}
	return ""
}

// interestingHostnameKeyword returns the first juicy keyword found in the
// hostname labels of rawURL (registrable domain excluded), or "".
func interestingHostnameKeyword(rawURL string) string {
	u, err := url.Parse(rawURL)
	if err != nil {
		return ""
	}
	host := strings.ToLower(u.Hostname())
	if host == "" || isIPAddress(host) {
		return ""
	}

	labels := strings.Split(host, ".")
	// Drop the registrable domain: it names the target, not an environment.
	drop := 2
	if len(labels) >= 3 && secondLevelDomainLabels[labels[len(labels)-2]] {
		drop = 3
	}
	if len(labels) <= drop {
		return ""
	}
	labels = labels[:len(labels)-drop]

	for _, label := range labels {
		if label == "www" {
			continue
		}
		for _, token := range strings.FieldsFunc(label, func(r rune) bool { return r == '-' || r == '_' }) {
			token = trailingDigitsPattern.ReplaceAllString(token, "")
			if token == "" {
				continue
			}
			for _, kw := range interestingHostnameTokens {
				if token == kw {
					return kw
				}
			}
		}
		if interestingHostnameAffixStoplist[label] {
			continue
		}
		for _, kw := range interestingHostnameAffixes {
			if len(label) > len(kw) && (strings.HasPrefix(label, kw) || strings.HasSuffix(label, kw)) {
				return kw
			}
		}
	}
	return ""
}

func isIPAddress(host string) bool {
	if strings.Contains(host, ":") {
		return true
	}
	for _, r := range host {
		if (r < '0' || r > '9') && r != '.' {
			return false
		}
	}
	return true
}
