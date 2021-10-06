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

func TestLooseParser(t *testing.T) {
	type args struct {
		lines  []string
		engine func(d string) string
		minLen int
	}

	testcase := []struct {
		args args
		want []string
	}{
		{
			args: args{lines: []string{"https://example.com"}, engine: DomainParser, minLen: 1},
			want: []string{"https://example.com"},
		},
	}

	for _, tt := range testcase {
		t.Run("", func(t *testing.T) {
			if got := LooseParser(tt.args.lines, tt.args.engine, tt.args.minLen); !reflect.DeepEqual(got, tt.want) {
				t.Errorf("LooseParser() = %v, want %v", got, tt.want)
			}
		})
	}
}
