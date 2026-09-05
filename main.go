package main

import (
	"bufio"
	"encoding/json"
	"fmt"
	"io/ioutil"
	"net/url"
	"os"
	"strings"
	"time"

	"github.com/google/uuid"
	"github.com/supr4s/aiquatone/agents"
	"github.com/supr4s/aiquatone/core"
	"github.com/supr4s/aiquatone/parsers"
)

var (
	sess *core.Session
	err  error
)

func isURL(s string) bool {
	u, err := url.ParseRequestURI(s)
	if err != nil {
		return false
	}
	if u.Scheme == "" {
		return false
	}
	return true
}

func hasSupportedScheme(s string) bool {
	u, err := url.ParseRequestURI(s)
	if err != nil {
		return false
	}
	if u.Scheme == "http" || u.Scheme == "https" {
		return true
	}
	return false
}

func renderReport(session *core.Session, template []byte, destination string) error {
	report := core.NewReport(session, string(template))
	f, err := os.Create(destination)
	if err != nil {
		return err
	}

	if err := report.Render(f); err != nil {
		_ = f.Close()
		return err
	}

	return f.Close()
}

func main() {
	if sess, err = core.NewSession(); err != nil {
		fmt.Println(err)
		os.Exit(1)
	}

	if *sess.Options.Version {
		sess.Out.Info("%s v%s", core.Name, core.Version)
		os.Exit(0)
	}

	fi, err := os.Stat(*sess.Options.OutDir)

	if os.IsNotExist(err) {
		if err := os.MkdirAll(*sess.Options.OutDir, 0755); err != nil {
			sess.Out.Fatal("Failed to create output destination %s: %s\n", *sess.Options.OutDir, err)
			os.Exit(1)
		}
		sess.Out.Info("Created output directory %s\n", *sess.Options.OutDir)
	} else if err != nil {
		sess.Out.Fatal("Cannot access output destination %s: %s\n", *sess.Options.OutDir, err)
		os.Exit(1)
	} else if !fi.IsDir() {
		sess.Out.Fatal("Output destination must be a directory\n")
		os.Exit(1)
	}

	sess.Out.Important("%s v%s started at %s\n\n", core.Name, core.Version, sess.Stats.StartedAt.Format(time.RFC3339))

	if *sess.Options.SessionPath != "" {
		jsonSession, err := ioutil.ReadFile(*sess.Options.SessionPath)
		if err != nil {
			sess.Out.Fatal("Unable to read session file at %s: %s\n", *sess.Options.SessionPath, err)
			os.Exit(1)
		}

		var parsedSession core.Session
		if err := json.Unmarshal(jsonSession, &parsedSession); err != nil {
			sess.Out.Fatal("Unable to parse session file at %s: %s\n", *sess.Options.SessionPath, err)
			os.Exit(1)
		}

		sess.Out.Important("Loaded AIquatone session at %s\n", *sess.Options.SessionPath)
		sess.Out.Important("Generating HTML report...")
		var template []byte
		if *sess.Options.TemplatePath != "" {
			template, err = ioutil.ReadFile(*sess.Options.TemplatePath)
		} else {
			template, err = sess.Asset("static/report_template.html")
		}

		if err != nil {
			sess.Out.Fatal("Can't read report template file\n")
			os.Exit(1)
		}

		if err = renderReport(&parsedSession, template, sess.GetFilePath("aiquatone_report.html")); err != nil {
			sess.Out.Fatal("Error during report generation: %s\n", err)
			os.Exit(1)
		}
		sess.Out.Important(" done\n\n")
		sess.Out.Important("Wrote HTML report to: %s\n\n", sess.GetFilePath("aiquatone_report.html"))
		os.Exit(0)
	}

	agents.NewTCPPortScanner().Register(sess)
	agents.NewURLPublisher().Register(sess)
	agents.NewURLRequester().Register(sess)
	agents.NewURLHostnameResolver().Register(sess)
	agents.NewURLPageTitleExtractor().Register(sess)
	agents.NewURLScreenshotter().Register(sess)
	agents.NewURLTechnologyFingerprinter().Register(sess)

	reader := bufio.NewReader(os.Stdin)
	var targets []string

	if *sess.Options.Nmap {
		parser := parsers.NewNmapParser()
		targets, err = parser.Parse(reader)
		if err != nil {
			sess.Out.Fatal("Unable to parse input as Nmap/Masscan XML: %s\n", err)
			os.Exit(1)
		}
	} else {
		parser := parsers.NewRegexParser()
		targets, err = parser.Parse(reader)
		if err != nil {
			sess.Out.Fatal("Unable to parse input.\n")
			os.Exit(1)
		}
	}

	if len(targets) == 0 {
		sess.Out.Fatal("No targets found in input.\n")
		os.Exit(1)
	}

	sess.Out.Important("Targets    : %d\n", len(targets))
	sess.Out.Important("Threads    : %d\n", *sess.Options.Threads)
	sess.Out.Important("Ports      : %s\n", strings.Trim(strings.Replace(fmt.Sprint(sess.Ports), " ", ", ", -1), "[]"))
	sess.Out.Important("Output dir : %s\n\n", *sess.Options.OutDir)

	sess.EventBus.Publish(core.SessionStart)

	batchSize := *sess.Options.Threads * 3
	if batchSize < 10 {
		batchSize = 10
	}

	var urls []string
	var hosts []string
	for _, target := range targets {
		if isURL(target) {
			if hasSupportedScheme(target) {
				urls = append(urls, target)
			}
		} else {
			hosts = append(hosts, target)
		}
	}

	for i := 0; i < len(hosts); i += batchSize {
		end := i + batchSize
		if end > len(hosts) {
			end = len(hosts)
		}
		for _, host := range hosts[i:end] {
			sess.EventBus.Publish(core.Host, host)
		}
		if end < len(hosts) {
			time.Sleep(100 * time.Millisecond)
		}
	}

	for i := 0; i < len(urls); i += batchSize {
		end := i + batchSize
		if end > len(urls) {
			end = len(urls)
		}
		for _, u := range urls[i:end] {
			sess.EventBus.Publish(core.URL, u)
		}
		if end < len(urls) {
			time.Sleep(200 * time.Millisecond)
		}
	}

	time.Sleep(3 * time.Second)
	sess.EventBus.WaitAsync()
	sess.WaitGroup.Wait()
	time.Sleep(2 * time.Second)
	sess.EventBus.WaitAsync()
	sess.WaitGroup.Wait()

	sess.EventBus.Publish(core.SessionEnd)
	time.Sleep(1 * time.Second)
	sess.EventBus.WaitAsync()
	sess.WaitGroup.Wait()

	sess.Out.Important("Calculating page structures...")
	urlsFile, err := os.Create(sess.GetFilePath("aiquatone_urls.txt"))
	if err != nil {
		sess.Out.Fatal("Unable to create URL output file: %s\n", err)
		os.Exit(1)
	}
	for _, page := range sess.Pages {
		if _, err := fmt.Fprintln(urlsFile, page.URL); err != nil {
			sess.Out.Error("Failed to write URL %s: %s\n", page.URL, err)
		}

		filename := sess.GetFilePath(fmt.Sprintf("html/%s.html", page.BaseFilename()))
		body, err := os.Open(filename)
		if err != nil {
			continue
		}
		structure, _ := core.GetPageStructure(body)
		if err := body.Close(); err != nil {
			sess.Out.Debug("Failed to close HTML body file %s: %s\n", filename, err)
		}
		page.PageStructure = structure
	}
	if err := urlsFile.Close(); err != nil {
		sess.Out.Error("Failed to close URL output file: %s\n", err)
	}
	sess.Out.Important(" done\n")

	sess.Out.Important("Clustering similar pages...")
	for _, page := range sess.Pages {
		foundCluster := false
		for clusterUUID, cluster := range sess.PageSimilarityClusters {
			addToCluster := true
			for _, pageURL := range cluster {
				page2 := sess.GetPage(pageURL)
				if page2 != nil && core.GetSimilarity(page.PageStructure, page2.PageStructure) < 0.80 {
					addToCluster = false
					break
				}
			}

			if addToCluster {
				foundCluster = true
				sess.PageSimilarityClusters[clusterUUID] = append(sess.PageSimilarityClusters[clusterUUID], page.URL)
				break
			}
		}

		if !foundCluster {
			newClusterUUID := uuid.New().String()
			sess.PageSimilarityClusters[newClusterUUID] = []string{page.URL}
		}
	}
	sess.Out.Important(" done\n")
	sess.End()

	sess.Out.Important("Generating HTML report...")
	var template []byte
	if *sess.Options.TemplatePath != "" {
		template, err = ioutil.ReadFile(*sess.Options.TemplatePath)
	} else {
		template, err = sess.Asset("static/report_template.html")
	}

	if err != nil {
		sess.Out.Fatal("Can't read report template file\n")
		os.Exit(1)
	}
	if err = renderReport(sess, template, sess.GetFilePath("aiquatone_report.html")); err != nil {
		sess.Out.Fatal("Error during report generation: %s\n", err)
		os.Exit(1)
	}
	sess.Out.Important(" done\n\n")

	sess.Out.Important("Writing session file...")
	err = sess.SaveToFile("aiquatone_session.json")
	if err != nil {
		sess.Out.Error("Failed!\n")
		sess.Out.Debug("Error: %v\n", err)
	}

	sess.Out.Important("Time:\n")
	sess.Out.Info(" - Started at  : %v\n", sess.Stats.StartedAt.Format(time.RFC3339))
	sess.Out.Info(" - Finished at : %v\n", sess.Stats.FinishedAt.Format(time.RFC3339))
	sess.Out.Info(" - Duration    : %v\n\n", sess.Stats.Duration().Round(time.Second))

	sess.Out.Important("Requests:\n")
	sess.Out.Info(" - Successful : %v\n", sess.Stats.RequestSuccessful)
	sess.Out.Info(" - Failed     : %v\n\n", sess.Stats.RequestFailed)

	sess.Out.Info(" - 2xx : %v\n", sess.Stats.ResponseCode2xx)
	sess.Out.Info(" - 3xx : %v\n", sess.Stats.ResponseCode3xx)
	sess.Out.Info(" - 4xx : %v\n", sess.Stats.ResponseCode4xx)
	sess.Out.Info(" - 5xx : %v\n\n", sess.Stats.ResponseCode5xx)

	sess.Out.Important("Screenshots:\n")
	sess.Out.Info(" - Successful : %v\n", sess.Stats.ScreenshotSuccessful)
	sess.Out.Info(" - Failed     : %v\n\n", sess.Stats.ScreenshotFailed)

	sess.Out.Important("Wrote HTML report to: %s\n\n", sess.GetFilePath("aiquatone_report.html"))
}
