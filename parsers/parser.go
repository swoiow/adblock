package parsers

import "strings"

var engines = []func(s string) string{
	HostParser,
	SurgeParser,
	DnsmasqParser,
	DomainParser,
}

func ParserSingle(line string, engine func(d string) string, minLen int) (bool, string) {
	if IsCommentOrEmptyLine(line) {
		return false, ""
	}

	var domain = engine(line)
	if IsDomainNamePlus(domain, minLen) {
		return true, domain
	} else {
		// to debug
		//fmt.Printf("Handle domain: `%s` failed after parse.\n", domain)
		return false, ""
	}
}

func Parser(lines []string, engine func(d string) string, minLen int) []string {
	var bucket []string

	for _, line := range lines {
		result, domain := ParserSingle(line, engine, minLen)
		if result {
			bucket = append(bucket, domain)
		}
	}
	return bucket
}

func FuzzyParser(lines []string, minLen int) []string {
	var bucket []string

	for _, line := range lines {
		if IsCommentOrEmptyLine(line) {
			continue
		}

		for _, engine := range engines {
			result, domain := ParserSingle(line, engine, minLen)
			if result && strings.Contains(domain, ".") {
				bucket = append(bucket, domain)
				break
			}
		}
	}
	return bucket
}
