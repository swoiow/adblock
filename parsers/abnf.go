package parsers

import "strings"

const (
	PrefixFlag = "||"
	SuffixFlag = "^"
)

// ABNFParser :
//	wildcard parser
func ABNFParser(d string) []string {
	if !strings.HasPrefix(d, PrefixFlag) && !strings.HasSuffix(d, SuffixFlag) {
		return nil
	}

	d = strings.TrimPrefix(d, PrefixFlag)
	d = strings.TrimSuffix(d, SuffixFlag)
	d = strings.TrimSpace(d)
	return []string{"*." + d, d}
}
