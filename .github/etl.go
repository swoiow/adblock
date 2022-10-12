package main

import (
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"net/http"
	"os"
	"strings"

	"github.com/bits-and-blooms/bloom/v3"
	"github.com/swoiow/blocked"
	"github.com/swoiow/dns_utils/loader"
	"github.com/swoiow/dns_utils/parsers"
)

const (
	rulesetPath = ".github/ruleset.txt"
	rulesetData = "rules.dat"
)

var (
	defaultConfigs = blocked.NewConfigs()
	Size           = uint(defaultConfigs.Size)
	Rate           = defaultConfigs.Rate
)

type githubIssue struct {
	Body string `json:"body"`
}

func fetchUrls() []string {
	url := "https://api.github.com/repos/swoiow/blocked/issues/comments/932148163"
	method := "GET"

	client := &http.Client{}
	req, err := http.NewRequest(method, url, nil)

	if err != nil {
		panic(err)

	}
	req.Header.Add("Accept", "application/vnd.github.v3+json")

	res, err := client.Do(req)
	if err != nil {
		panic(err)
	}
	defer res.Body.Close()

	body, err := io.ReadAll(res.Body)
	if err != nil {
		panic(err)
	}

	jsonb := githubIssue{}
	err = json.Unmarshal(body, &jsonb)
	if err != nil {
		panic(err)
	}

	urls := strings.Split(jsonb.Body, "\r\n")
	var urlRules []string
	for _, i := range urls {
		if len(strings.TrimSpace(i)) > 0 {
			urlRules = append(urlRules, i)
		}
	}
	return urlRules
}

func createRuleset(ruleUrls []string) {
	tmpDataPath := ".github/rules"
	if _, err := os.Stat(tmpDataPath); errors.Is(err, os.ErrNotExist) {
		os.MkdirAll(tmpDataPath, 777)
	}

	// load drop-domains so that can drop the useless rules.
	dropSet := make(map[string]bool)
	dropRules, _ := loader.UrlToLines("https://github.com/swoiow/blocked/raw/conf/dat/drop-domains.txt")
	for _, dropRule := range dropRules {
		dropSet[dropRule] = true
	}

	// begin logic
	ruleSet := make(map[string]bool)
	for _, ruleUrl := range ruleUrls {
		lines, err := loader.UrlToLines(ruleUrl)
		if err != nil {
			panic(err)
		}

		// handle by parsers
		last := len(ruleSet)
		lines = parsers.FuzzyParser(lines, 3)

		ph := strings.Replace(ruleUrl, "https://", "", -1)
		ph = strings.Replace(ph, ".", "_", -1)
		ph = strings.Replace(ph, "/", "_", -1)
		wFile, err := os.Create(tmpDataPath + "/" + ph)
		if err != nil {
			panic(err)
			os.Exit(1)
		}
		defer wFile.Close()
		wFile.WriteString(strings.Join(lines, "\n"))

		for _, line := range lines {
			domain := strings.ToLower(strings.TrimSpace(line))

			if dropSet[domain] {
				continue
			}

			if _, ok := ruleSet[domain]; !ok {
				ruleSet[domain] = true
			}
		}

		fmt.Printf("Loaded %s (num:%v) from `%s`.\n", "rules", len(ruleSet)-last, ruleUrl)
	}

	Size = uint(1.1 * float64(len(ruleSet)))
	filter := bloom.NewWithEstimates(Size, Rate)
	for r := range ruleSet {
		filter.AddString(r)
	}

	fmt.Printf("Total load: %v - Filter save: %v\n", len(ruleSet), filter.ApproximatedSize())

	// Save: rulesetData
	wFile, err := os.Create(rulesetData)
	if err != nil {
		panic(err)
		os.Exit(1)
	}
	defer wFile.Close()

	_, err = filter.WriteTo(wFile)

	// Save: rulesetPath
	wFile, err = os.Create(rulesetPath)
	if err != nil {
		panic(err)
		os.Exit(1)
	}
	defer wFile.Close()

	rules := make([]string, 0, len(ruleSet))
	for k := range ruleSet {
		rules = append(rules, k)
	}
	wFile.WriteString(strings.Join(rules, "\n"))
}

func main() {
	createRuleset(fetchUrls())
}
