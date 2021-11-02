package parsers

import (
	"testing"

	"github.com/google/go-cmp/cmp"
)

func TestABNFParser(t *testing.T) {
	tests := []struct {
		domain string
		expect []string
	}{
		{domain: "||example.com^", expect: []string{"*.example.com", "example.com"}},
	}
	for _, tt := range tests {
		t.Run("tt_"+tt.domain, func(t *testing.T) {
			domain := ABNFParser(tt.domain)
			if !cmp.Equal(domain, tt.expect) {
				t.Errorf("parser() result = %v, want %v", domain, tt.expect)
			}
		})
	}
}
