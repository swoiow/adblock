package blocked

import (
	"fmt"
	"os"
	"strings"
	"testing"

	bloom "github.com/seiflotfy/cuckoofilter"
	"github.com/swoiow/blocked/parsers"
)

const (
	rulesetPath = ".github/ruleset.txt"
	rulesetData = "rules.dat"
)

var defaultConfigs = NewConfigs()

func TestCreateCache(t *testing.T) {
	t.Skip()

	rules := &[]string{
		rulesetPath,
	}

	filter := bloom.NewFilter(uint(defaultConfigs.Size))

	for _, rule := range *rules {
		_ = LocalRuleLoader(rule, filter, false)
	}

	wFile, err := os.Create(rulesetData)
	if err != nil {
		log.Error(err)
		os.Exit(1)
	}
	defer wFile.Close()

	wFile.Write(filter.Encode())
	fmt.Printf("Saved %v about %v rules from filter.", "", filter.Count())
}

func TestCacheByLocal(t *testing.T) {
	filter, err := LocalCacheLoader(rulesetData)
	if err != nil {
		panic(err)
	}

	type rule struct {
		name   string
		result bool
	}

	var items = []rule{
		{name: "baidu.com", result: false},
		{name: "reddit.com", result: false},
		{name: "xhscdn.com", result: false},
		{name: "*.xhscdn.com", result: false},
	}

	for _, tt := range items {
		t.Run(tt.name, func(t *testing.T) {
			if resp := filter.Lookup([]byte(tt.name)); resp != tt.result {
				t.Errorf("TestCache failed %v", tt.name)
			}
		})
	}
}

func TestCacheByFile(t *testing.T) {
	filter, err := LocalCacheLoader(rulesetData)
	if err != nil {
		panic(err)
	}

	type rule struct {
		name   string
		result bool
	}
	var items = []rule{}
	lines, _ := FileToLines(rulesetPath)

	for _, line := range lines {
		result, domains := parsers.Parse(line, parsers.DomainParser)
		items = append(items, rule{name: strings.ToLower(domains[0]), result: result})
	}

	for _, tt := range items {
		t.Run(tt.name, func(t *testing.T) {
			if resp := filter.Lookup([]byte(tt.name)); resp != tt.result {
				t.Errorf("TestCache failed %v", tt.name)
			}
		})
	}
}
