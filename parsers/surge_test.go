package parsers

import "testing"

func TestShieldParser(t *testing.T) {
	tests := []struct {
		domain string
		expect bool
		result string
	}{
		{domain: "# DOMAIN,example.com,REJECT", expect: false, result: ""},
		{domain: "# DOMAIN,example.com,reject", expect: false, result: ""},
		{domain: "DOMAIN,127.0.0.1,reject", expect: false, result: ""},
		{domain: "DOMAIN,1.0.0.1,reject", expect: false, result: ""},
		{domain: "DOMAIN,example.com/example,reject", expect: false, result: ""},
		{domain: "DOMAIN,example.com/example/example,reject", expect: false, result: ""},

		{domain: "DOMAIN,example,reject", expect: true, result: "example"},
		{domain: "DOMAIN,example.com,REJECT", expect: true, result: "example.com"},
		{domain: "DOMAIN,example.com,reject", expect: true, result: "example.com"},
	}
	for _, tt := range tests {
		t.Run("tt_"+tt.domain, func(t *testing.T) {
			result, domain := ParserSingle(tt.domain, SurgeParser, 1)
			if result != tt.expect {
				t.Errorf("parser() got = %v, want %v", result, tt.expect)
			}

			if result && domain != tt.result {
				t.Errorf("parser() result = %v, want %v", result, tt.result)
			}
		})
	}
}
