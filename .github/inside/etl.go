package main

import (
	"fmt"
	"io/ioutil"
	"os"
	"strconv"
	"strings"

	cuckoo "github.com/seiflotfy/cuckoofilter"
	"github.com/swoiow/blocked"
	"github.com/swoiow/blocked/parsers"
)

const (
	rulesetPath = ".github/inside.txt"
	rulesetData = "inside.dat"
)

var (
	Size = 500_000
)

func createRules(ruleUrls []string) []string {
	ruleSet := map[string]bool{}
	ruleSet["*.cn"] = true

	for _, ruleUrl := range ruleUrls {
		lines, err := blocked.UrlToLines(ruleUrl)
		if err != nil {
			panic(err)
		}

		// handle by parsers
		last := len(ruleSet)
		lines = parsers.FuzzyParser(lines, 3)
		for _, line := range lines {
			domain := strings.ToLower(strings.TrimPrefix(strings.TrimSuffix(strings.TrimSpace(line), "."), "*."))

			dotCount := strings.Count(domain, ".")
			if strings.HasSuffix(domain, ".cn") {
				continue
			} else if dotCount == 1 {
				if !ruleSet[domain] {
					ruleSet[domain] = true
				}
				if !ruleSet["*."+domain] {
					ruleSet["*."+domain] = true
				}
			} else if dotCount > 1 {
				hasAdd := false
				firstFlag := true
				splitHost := strings.Split(domain, ".")
				newHost := ""
				for i := len(splitHost) - 1; i > 0; i-- {
					if firstFlag {
						newHost = splitHost[i]
						firstFlag = false
					} else {
						newHost = splitHost[i] + "." + newHost
						if ruleSet[newHost] || ruleSet["*."+newHost] {
							hasAdd = true
							break
						}
					}
				}

				if !hasAdd {
					ruleSet[domain] = true
					// ruleSet["*."+domain] = true
				}
			}
		}

		fmt.Printf("Loaded %s (num:%v) from `%s`.\n", "rules", len(ruleSet)-last, ruleUrl)
	}

	fmt.Printf("\nTotal load: %v", len(ruleSet))

	// Save: rulesetPath
	rules := saveAsTxt(ruleSet)
	return rules
}

func saveAsDat(rules []string) {
	filter := cuckoo.NewFilter(uint(Size))

	for _, rule := range rules {
		// println(rule)
		filter.InsertUnique([]byte(rule))
	}

	// fmt.Printf("Total load: %v", len(rules))

	// Save: rulesetData
	wFile, err := os.Create(rulesetData)
	if err != nil {
		panic(err)
		os.Exit(1)
	}
	defer wFile.Close()

	wFile.Write(filter.Encode())

	fmt.Printf("filter saving : %v\n", filter.Count())
}

func saveAsTxt(ruleSet map[string]bool) []string {
	wFile, err := os.Create(rulesetPath)
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
	return rules
}

func testDat() error {
	counter := 0
	rf, err := os.Open(rulesetData)
	if err != nil {
		return err
	}
	defer rf.Close()
	body, err := ioutil.ReadAll(rf)
	bottle, err := cuckoo.Decode(body)
	if err != nil {
		return err
	}

	lines, _ := blocked.FileToLines(rulesetPath)

	for _, line := range lines {
		if bottle.Lookup([]byte(line)) {
			counter += 1
		} else {
			fmt.Println(line)
		}
	}

	fmt.Println(bottle.Count(), counter)
	return nil
}

func main() {
	selected := 1
	if v := os.Getenv("ETL_MODE"); v != "" {
		selected, _ = strconv.Atoi(v)
	}

	switch selected {
	case 1:
		data := createRules([]string{
			"https://raw.githubusercontent.com/Loyalsoldier/v2ray-rules-dat/release/direct-list.txt",
			"https://raw.githubusercontent.com/swoiow/app-domains/main/app-domains.txt",
		})
		saveAsDat(data)

	default:
		_ = testDat()
	}
}
