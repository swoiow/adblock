package parsers

import (
	"testing"

	"github.com/google/go-cmp/cmp"
)

func TestSurgeParser(t *testing.T) {
	tests := []struct {
		domain string
		expect bool
		result []string
	}{
		{domain: "", expect: false, result: nil},
		{domain: "http://example.com", expect: false, result: nil},

		{domain: "# DOMAIN,example.com,REJECT", expect: false, result: nil},
		{domain: "# DOMAIN,example.com,reject", expect: false, result: nil},
		{domain: "DOMAIN,127.0.0.1,reject", expect: false, result: nil},
		{domain: "DOMAIN,1.0.0.1,reject", expect: false, result: nil},
		{domain: "DOMAIN,example.com/example,reject", expect: false, result: nil},
		{domain: "DOMAIN,example.com/example/example,reject", expect: false, result: nil},

		{domain: "DOMAIN,example,reject", expect: true, result: []string{"example"}},
		{domain: "DOMAIN,example.com,REJECT", expect: true, result: []string{"example.com"}},
		{domain: "DOMAIN,example.com,reject", expect: true, result: []string{"example.com"}},

		{domain: " DOMAIN,example.com,reject", expect: true, result: []string{"example.com"}},
		{domain: "	DOMAIN,example.com,reject", expect: true, result: []string{"example.com"}},
		// {domain: "DOMAIN-SUFFIX,example.com,reject", expect: true, result: []string{"*.example.com", "example.com"}},
	}
	for _, tt := range tests {
		t.Run("tt_"+tt.domain, func(t *testing.T) {
			result, domain := Parse(tt.domain, SurgeParser)
			if result != tt.expect {
				t.Errorf("parser() got = %v, want %v", result, tt.expect)
			}

			if result && !cmp.Equal(domain, tt.result) {
				t.Errorf("parser() result = %v, want %v", result, tt.result)
			}
		})
	}
}
