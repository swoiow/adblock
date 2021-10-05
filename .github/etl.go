package main

import (
	"encoding/json"
	"fmt"
	"github.com/bits-and-blooms/bloom/v3"
	blocked "github.com/swoiow/adblock"
	"github.com/swoiow/adblock/parsers"
	"io/ioutil"
	"net/http"
	"os"
	"strings"
)

const (
	rulesetPath = ".github/ruleset.txt"
	rulesetData = "rules.dat"
)

type githubIssue struct {
	Body string `json:"body"`
}

func fetchUrls() []string {
	url := "https://api.github.com/repos/swoiow/adblock/issues/comments/932148163"
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

	body, err := ioutil.ReadAll(res.Body)
	if err != nil {
		panic(err)
	}

	jsonb := githubIssue{}
	err = json.Unmarshal(body, &jsonb)
	if err != nil {
		panic(err)
	}

	urls := strings.Split(jsonb.Body, "\r\n")
	return urls
}

func createRuleset(rules []string) {
	defaultConfigs := blocked.DefaultConfigs()

	ruleset := []string{}
	number := 0
	filter := bloom.NewWithEstimates(uint(defaultConfigs.Size), defaultConfigs.Rate)
	for _, ruleUrl := range rules {
		lines, err := blocked.UrlToLines(ruleUrl)
		if err != nil {
			panic(err)
		}

		// handle by parsers
		c := 0
		lines = parsers.FuzzyParser(lines, 3)
		for _, line := range lines {
			domain := strings.ToLower(strings.TrimSpace(line))
			if !filter.TestAndAddString(domain) {
				c += 1
				ruleset = append(ruleset, domain)
			}
		}
		fmt.Printf("Loaded %s (num:%v) from `%s`.\n", "rules", c, ruleUrl)

		number += c
	}

	fmt.Printf("Total load: %v", number)

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

	wFile.WriteString(strings.Join(ruleset, "\n"))
}

func main() {
	createRuleset(fetchUrls())
}
