package parsers

import "strings"

const (
	fSlashMark = "/"
)

func DnsmasqParser(d string) string {
	if !strings.Contains(d, fSlashMark) {
		return ""
	}

	d = strings.Split(d, fSlashMark)[1]
	return strings.TrimSpace(d)
}
