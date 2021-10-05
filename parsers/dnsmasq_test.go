package parsers

import (
	"testing"
)

func TestDnsmasqParser(t *testing.T) {
	tests := []struct {
		domain string
		expect bool
	}{
		{domain: "# server=/example.com/1.1.1.1", expect: false},
		{domain: "server=/example.com/1.1.1.1", expect: true},
		{domain: "server=/example.com/", expect: true},
		{domain: "server=/example.com /", expect: true},
		{domain: "server=/example.com / ", expect: true},
	}
	for _, tt := range tests {
		t.Run("tt_"+tt.domain, func(t *testing.T) {
			result, domain := ParserSingle(tt.domain, DnsmasqParser, 1)
			if result != tt.expect {
				t.Errorf("parser() got = %v, want %v", result, tt.expect)
			} else {
				if result && domain != "example.com" {
					t.Errorf("parser() result = %v, want %v", result, "example.com")
				}
			}
		})
	}
}
