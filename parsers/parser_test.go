package parsers

import (
	"reflect"
	"testing"
)

func TestFuzzyParser(t *testing.T) {

	testcase := struct {
		lines []string
		want  []string
	}{

		lines: []string{
			"server=/example.com/1.1.1.1",
			"example.com",
			"DOMAIN,example.com,REJECT",

			"server=/example/1.1.1.1",
			"example",
			"DOMAIN,example,REJECT",

			"#server=/example.com/1.1.1.1",
			"#example.com",
			"#DOMAIN,example.com,REJECT",

			" #server=/example.com/1.1.1.1",
			" #example.com",
			" #DOMAIN,example.com,REJECT",

			"http://example.com",
			"https://example.com",
		},
		want: []string{
			"example.com",
			"example.com",
			"example.com",
		},
	}

	t.Run("example.com", func(t *testing.T) {
		if got := FuzzyParser(testcase.lines, 1); !reflect.DeepEqual(got, testcase.want) {
			t.Errorf("FuzzyParser() = %v, want %v", got, testcase.want)
		}
	})
}
