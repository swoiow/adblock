package main

import (
	"fmt"
	"os"
	"strings"

	"github.com/bits-and-blooms/bloom/v3"
	"github.com/swoiow/blocked"
	"github.com/swoiow/dns_utils/parsers"
)

const (
	rulesetPath = ".github/inside.txt"
	rulesetData = "inside.dat"
)

var (
	Size = 100_000
	Cap  = 0.001
)

func generateDAT(rules []string) {
	filter := bloom.NewWithEstimates(uint(Size), Cap)

	for _, rule := range rules {
		filter.AddString(rule)
	}

	// fmt.Printf("Total load: %v", len(rules))

	// Save: rulesetData
	wFile, err := os.Create(rulesetData)
	if err != nil {
		panic(err)
		os.Exit(1)
	}
	defer wFile.Close()

	_, err = filter.WriteTo(wFile)

	fmt.Printf("\nfilterK: %v - filterCap:%s. filter loads: %v", filter.K(), filter.Cap(), filter.ApproximatedSize())

	// // Save: rulesetPath
	// wFile, err = os.Create(rulesetPath)
	// if err != nil {
	// 	panic(err)
	// 	os.Exit(1)
	// }
	// defer wFile.Close()
	//
	// rules := make([]string, 0, len(ruleset))
	// for k := range ruleset {
	// 	rules = append(rules, k)
	// }
	// wFile.WriteString(strings.Join(rules, "\n"))
}

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

	Size = int(1.1 * float64(len(ruleSet)))

	// Save: rulesetPath
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

func testDAT() {
	counter := 0
	bottle := bloom.NewWithEstimates(uint(Size), Cap)

	blocked.LocalCacheLoader(rulesetData, bottle)

	lines, _ := blocked.FileToLines(rulesetPath)

	for _, line := range lines {
		if bottle.TestString(line) {
			counter += 1
		} else {
			fmt.Println(line)
		}
	}

	fmt.Println(bottle.K(), bottle.Cap(), counter)
}

func main() {
	selected := 1

	switch selected {
	case 1:
		data := createRules([]string{
			"https://raw.githubusercontent.com/Loyalsoldier/v2ray-rules-dat/release/direct-list.txt",
			"https://raw.githubusercontent.com/swoiow/app-domains/main/app-domains.txt",
		})
		generateDAT(data)

	default:
		testDAT()
	}
}
