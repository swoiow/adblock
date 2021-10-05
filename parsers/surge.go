package parsers

import "strings"

const (
	rejectFlag = ",reject"
	commaMark  = ","
)

func SurgeParser(d string) string {
	if !strings.HasSuffix(strings.ToLower(d), rejectFlag) {
		return ""
	}

	d = strings.Split(d, commaMark)[1]
	return strings.TrimSpace(d)
}
