package main

import (
	"encoding/json"
	"fmt"
	"io/ioutil"
	"net/http"
	"os"
	"strconv"
	"strings"

	bloom "github.com/seiflotfy/cuckoofilter"
	"github.com/swoiow/blocked"
	"github.com/swoiow/blocked/parsers"
)

const (
	rulesetPath = ".github/ruleset.txt"
	rulesetData = "rules.dat"
)

var (
	Size = 500_000
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
	var bucket []string
	for _, i := range urls {
		if len(strings.TrimSpace(i)) > 0 {
			bucket = append(bucket, i)
		}
	}
	return bucket
}

func createRuleSet(ruleUrls []string) map[string]bool {
	ruleSet := make(map[string]bool)
	for _, ruleUrl := range ruleUrls {
		lines, err := blocked.UrlToLines(ruleUrl)
		if err != nil {
			panic(err)
		}

		// handle by parsers
		last := len(ruleSet)
		lines = parsers.FuzzyParser(lines, 3)
		for _, line := range lines {
			domain := strings.ToLower(strings.TrimSpace(line))

			if strings.Count(domain, ".") >= 3 {
				d := strings.Split(domain, ".")
				domain = strings.Join(d[len(d)-3:], ".")
			}

			if _, ok := ruleSet[domain]; !ok {
				ruleSet[domain] = true
			}
		}

		fmt.Printf("Loaded %s (num:%v) from `%s`.\n", "rules", len(ruleSet)-last, ruleUrl)
	}
	return ruleSet
}

func saveAsDat(ruleSet map[string]bool) {
	filter := bloom.NewFilter(uint(Size))
	for rule := range ruleSet {
		filter.InsertUnique([]byte(rule))
	}

	fmt.Printf("Total load: %v - Filter save: %v\n", len(ruleSet), filter.Count())

	wFile, err := os.Create(rulesetData)
	if err != nil {
		panic(err)
		os.Exit(1)
	}
	defer wFile.Close()

	wFile.Write(filter.Encode())
}

func saveAsTxt(ruleSet map[string]bool) {
	wFile, err := os.Create(rulesetPath)
	if err != nil {
		panic(err)
		os.Exit(1)
	}

	rules := make([]string, 0, len(ruleSet))
	for k := range ruleSet {
		rules = append(rules, k)
	}
	wFile.WriteString(strings.Join(rules, "\n"))
}

type domains []string

// func createRulesetV2(ruleUrls []string) {
// 	ruleSet := make(map[string]domains)
//
// 	for _, ruleUrl := range ruleUrls {
// 		lines, err := blocked.UrlToLines(ruleUrl)
// 		if err != nil {
// 			panic(err)
// 		}
//
// 		// handle by parsers
// 		count := 0
// 		lines = parsers.FuzzyParser(lines, 3)
// 		for _, line := range lines {
// 			originDomain := strings.ToLower(strings.TrimSpace(line))
//
// 			lv3Domain := originDomain
// 			if strings.Count(originDomain, ".") >= 4 {
// 				d := strings.Split(originDomain, ".")
// 				lv3Domain = strings.Join(d[len(d)-4:], ".")
// 			}
//
// 			if !slices.Contains(ruleSet[lv3Domain], originDomain) {
// 				ruleSet[lv3Domain] = append(ruleSet[lv3Domain], originDomain)
// 				count += 1
// 			}
// 		}
//
// 		// fmt.Printf("Loaded %s (num:%v) from `%s`.\n", "rules", count, ruleUrl)
// 	}
//
// 	for s, d := range ruleSet {
// 		fmt.Printf("%s, %v\n", s, len(d))
// 	}
// }

func CacheRule(ruleUrls []string) {
	for _, ruleUrl := range ruleUrls {
		lines, err := blocked.UrlToLines(ruleUrl)

		fn := strings.Split(ruleUrl, "/")
		fn = fn[len(fn)-1:]
		wFile, err := os.Create(strings.Join([]string{".github", "rules", fn[0]}, "/"))
		if err != nil {
			panic(err)
			os.Exit(1)
		}
		defer wFile.Close()

		wFile.WriteString(strings.Join(lines, "\n"))

	}
}

func testDat() error {
	counter := 0
	rf, err := os.Open(rulesetData)
	if err != nil {
		return err
	}
	defer rf.Close()

	body, err := ioutil.ReadAll(rf)
	filter, err := bloom.Decode(body)
	if err != nil {
		return err
	}

	lines, _ := blocked.FileToLines(rulesetPath)

	for _, line := range lines {
		if filter.Lookup([]byte(line)) {
			counter += 1
		} else {
			fmt.Println(line)
		}
	}

	fmt.Println(filter.Count(), counter)
	return nil
}

func main() {
	selected := 1
	if v := os.Getenv("ETL_MODE"); v != "" {
		selected, _ = strconv.Atoi(v)
	}

	switch selected {

	// 1  for create rules.dat
	case 1:
		ruleSet := createRuleSet(fetchUrls())
		saveAsDat(ruleSet)
		saveAsTxt(ruleSet)
		return

	// 2 for fetch data rules data
	case 2:
		// createRulesetV2(fetchUrls())
		return // 2 for fetch data rules data

	// 3 for download all rule in local
	case 3:
		CacheRule(fetchUrls())
		return

	case 4:
		_ = testDat()
		return

	default:
		return
	}
}
