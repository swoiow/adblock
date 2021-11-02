package parsers

import "strings"

func DomainParser(s string) []string {
	d := strings.TrimSpace(s)
	return []string{d}
}
