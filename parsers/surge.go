package parsers

import "strings"

const (
	wildFlag   = "DOMAIN-SUFFIX"
	rejectFlag = ",reject"
	commaMark  = ","
)

func SurgeParser(d string) []string {
	wild := false
	if !strings.HasSuffix(strings.ToLower(d), rejectFlag) {
		return nil
	}

	if strings.HasPrefix(strings.ToUpper(d), wildFlag) {
		wild = true
	}

	d = strings.Split(d, commaMark)[1]
	d = strings.TrimSpace(d)

	if wild {
		return []string{"*." + strings.TrimPrefix(d, "."), d}
	} else {
		return []string{d}
	}
}
