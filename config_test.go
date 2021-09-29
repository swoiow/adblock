package adblock

import (
	"fmt"
	"github.com/bits-and-blooms/bloom/v3"
	"os"
	"testing"
)

func TestCreateCache(t *testing.T) {
	rules := &[]string{
		"rules.txt",
		"rules1.txt",
		"rules2.txt",
		"windows.txt",
		"privacy.txt",
	}

	filter := bloom.NewWithEstimates(uint(DefaultConfigs.Size), DefaultConfigs.Rate)

	for _, rule := range *rules {
		_ = LoadRuleByLocal(rule, filter)
	}

	wFile, err := os.Create("./rules.data")
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

	file, err := os.Open("./rules.data")
	if err != nil {
		fmt.Println(err)
		os.Exit(1)
	}
	defer file.Close()

	_, err = filter.ReadFrom(file)

	tests := []struct {
		name   string
		result bool
	}{
		{name: "a.ads1.msn.com", result: true},
		{name: "00-gov.cn", result: true},
		{name: "google.com", result: false},
		{name: "baidu.com", result: false},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			if resp := filter.TestString(tt.name); resp != tt.result {
				t.Errorf("TestCache failed %v", tt.name)
			}
		})
	}
}
