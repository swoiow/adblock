package parsers

import "testing"

func TestDomainParser(t *testing.T) {
	tests := []struct {
		domain string
		expect bool
	}{
		{domain: "", expect: false},
		{domain: "http://example.com", expect: false},

		{domain: "example.com\r", expect: true},
		{domain: "example.com\n", expect: true},
		{domain: "example.com\r\n", expect: true},

		{domain: " example.com\r\n", expect: true},
		{domain: "	example.com", expect: true},
	}
	for _, tt := range tests {
		t.Run("tt_"+tt.domain, func(t *testing.T) {
			got, _ := Parse(tt.domain, DomainParser)
			if got != tt.expect {
				t.Errorf("parser() got = %v, want %v", got, tt.expect)
			}
		})
	}
}
