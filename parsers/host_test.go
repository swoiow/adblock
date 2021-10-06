package parsers

import "testing"

func TestHostParser(t *testing.T) {

	tests := []struct {
		domain string
		expect bool
	}{
		{domain: "", expect: false},
		{domain: "http://example.com", expect: false},

		{domain: "# 0.0.0.0 example.com", expect: false},
		{domain: "# 127.0.0.1 example.com", expect: false},
		{domain: "0.0.0.0 0.0.0.0", expect: false},
		{domain: "::1 localhost", expect: false},
		{domain: "::1 ip6-localhost", expect: false},
		{domain: "255.255.255.255 broadcasthost", expect: false},
		{domain: "! 127.0.0.1 example.com", expect: false},
		{domain: "= 127.0.0.1 example.com", expect: false},
		{domain: "127.0.0.1 _mail@dev.io", expect: false},
		{domain: "127.0.0.1 _mail#dev.io", expect: false},
		{domain: "127.0.0.1 ", expect: false},

		{domain: "0.0.0.0 example.com", expect: true},
		{domain: "127.0.0.1 example.com", expect: true},
		{domain: "127.0.0.1 .example.com.", expect: true},
		{domain: "127.0.0.1 .example.com/", expect: true},
		{domain: "127.0.0.1 a.b.c.com", expect: true},
		{domain: "127.0.0.1 x", expect: true},
		{domain: "127.0.0.1 x.", expect: true},
		{domain: "127.0.0.1 .x.", expect: true},
		{domain: "127.0.0.1 .xy.", expect: true},
		{domain: "127.0.0.1 _", expect: true},
		{domain: "127.0.0.1 1-1-1-aaa.com", expect: true},

		{domain: " 127.0.0.1 .example.com.", expect: true},
		{domain: "	127.0.0.1 .example.com.", expect: true},
	}
	for _, tt := range tests {
		t.Run("tt_"+tt.domain, func(t *testing.T) {
			got, _ := Parse(tt.domain, HostParser)
			if got != tt.expect {
				t.Errorf("parser() got = %v, want %v", got, tt.expect)
			}
		})
	}
}
