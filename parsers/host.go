package parsers

import (
	"strings"
)

type MapList map[string]bool

const (
	ruleZero = "0.0.0.0 "
	rule127  = "127.0.0.1 "

	commentMark = " #"
)

func HostParser(d string) []string {
	d = strings.TrimSpace(d)
	if strings.HasPrefix(d, rule127) {
		d = strings.TrimPrefix(d, rule127)
	} else {
		d = strings.TrimPrefix(d, ruleZero)
	}

	d = strings.TrimPrefix(d, ".")
	d = strings.TrimSuffix(d, ".")
	d = strings.TrimSuffix(d, "/")

	d = strings.Split(d, commentMark)[0] // Some hosts file has comment
	d = strings.TrimSpace(d)
	return []string{d}
}
