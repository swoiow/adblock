package adblock

import (
	"fmt"
	"github.com/bits-and-blooms/bloom/v3"
	"os"
	"strings"
	"testing"
)

const (
	rulesetPath = ".github/ruleset.txt"
	rulesetData = "rules.dat"
)

func TestCreateCache(t *testing.T) {
	rules := &[]string{
		rulesetPath,
	}

	filter := bloom.NewWithEstimates(uint(DefaultConfigs.Size), DefaultConfigs.Rate)

	for _, rule := range *rules {
		_ = LoadRuleByLocal(rule, filter)
	}

	wFile, err := os.Create(rulesetData)
	if err != nil {
		log.Error(err)
		os.Exit(1)
	}
	defer wFile.Close()

	num, err := filter.WriteTo(wFile)
	fmt.Printf("Saved %v about %v rules from filter.", num, filter.K())
}

func TestCache(t *testing.T) {
	filter := bloom.NewWithEstimates(uint(DefaultConfigs.Size), DefaultConfigs.Rate)

	file, err := os.Open(rulesetData)
	if err != nil {
		fmt.Println(err)
		os.Exit(1)
	}
	defer file.Close()

	_, err = filter.ReadFrom(file)

	type rule struct {
		name   string
		result bool
	}

	var items []rule
	lines, _ := FileToLines(rulesetPath)
	for _, line := range lines {
		line = strings.ToLower(strings.TrimSpace(line))
		if strings.HasPrefix(line, "#") || len(line) <= 3 || len(line) > 64 {
			continue
		}
		items = append(items, rule{name: strings.ToLower(line), result: true})
	}

	for _, tt := range items {
		t.Run(tt.name, func(t *testing.T) {
			if resp := filter.TestString(tt.name); resp != tt.result {
				t.Errorf("TestCache failed %v", tt.name)
			}
		})
	}
}
