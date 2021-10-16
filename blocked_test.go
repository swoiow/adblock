package blocked

import (
	"strings"
	"testing"

	"github.com/bits-and-blooms/bloom/v3"
)

func TestBlackListOnly(t *testing.T) {
	// arrange
	host := "example.com"
	runCfg := DefaultConfigs()
	runCfg.filter = bloom.NewWithEstimates(uint(runCfg.Size), runCfg.Rate)
	addLines2filter([]string{host}, runCfg.filter)

	tests := []struct {
		host string
		want bool
	}{
		{host: "example." + host, want: false},

		{host: host, want: true},
		{host: strings.ToUpper(host), want: true},
		{host: host + ".", want: true},
	}
	for _, tt := range tests {
		t.Run(tt.host, func(t *testing.T) {
			if got := IsBlocked(runCfg, strings.ToLower(strings.TrimSuffix(tt.host, "."))); got != tt.want {
				t.Errorf("IsBlocked() = %v, want %v", got, tt.want)
			}
		})
	}
}

func TestBlackListWithWhiteList(t *testing.T) {
	// arrange
	host := "example.com"
	runCfg := DefaultConfigs()
	runCfg.whiteListMode = true

	runCfg.filter = bloom.NewWithEstimates(uint(runCfg.Size), runCfg.Rate)
	addLines2filter([]string{host, "example." + host}, runCfg.filter)

	runCfg.wFilter = bloom.NewWithEstimates(uint(runCfg.Size), runCfg.Rate)
	addLines2filter([]string{host}, runCfg.wFilter)

	tests := []struct {
		host string
		want bool
	}{
		{host: host, want: false},
		{host: strings.ToUpper(host), want: false},
		{host: host + ".", want: false},

		{host: "example." + host, want: true},
	}
	for _, tt := range tests {
		t.Run(tt.host, func(t *testing.T) {
			if got := IsBlocked(runCfg, strings.ToLower(strings.TrimSuffix(tt.host, "."))); got != tt.want {
				t.Errorf("IsBlocked() = %v, want %v", got, tt.want)
			}
		})
	}
}
