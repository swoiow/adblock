package parsers

import "strings"

const (
	fSlashMark = "/"
)

func DnsmasqParser(d string) []string {
	if !strings.Contains(d, fSlashMark) {
		return nil
	}

	d = strings.Split(d, fSlashMark)[1]
	d = strings.TrimSpace(d)
	return []string{d}
}
