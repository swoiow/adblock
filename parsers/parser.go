package parsers

var engines = []func(s string) string{
	HostParser,
	SurgeParser,
	DnsmasqParser,
	DomainParser,
}

func Parse(line string, engine func(d string) string) (bool, string) {
	if IsCommentOrEmptyLine(line) {
		return false, ""
	}

	var domain = engine(line)
	if IsDomainName(domain) {
		return true, domain
	} else {
		// to debug
		//fmt.Printf("Handle domain: `%s` failed after parse.\n", domain)
		return false, ""
	}
}

//func Parse(lines []string, engine func(d string) string) []string {
//	var bucket []string
//
//	for _, line := range lines {
//		result, domain := Parse(line, engine)
//		if result {
//			bucket = append(bucket, domain)
//		}
//	}
//	return bucket
//}

func LooseParser(lines []string, engine func(d string) string, minLen int) []string {
	var bucket []string

	for _, line := range lines {
		if !IsDomainNamePlus(line, minLen, false, false) {
			continue
		}
		domain := engine(line)
		bucket = append(bucket, domain)
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
			result, domain := Parse(line, engine)
			result = IsDomainNamePlus(domain, minLen, true, true)
			if result {
				//fmt.Printf("line: `%s` parsered by: %s\n", line, getFunctionName(engine))
				bucket = append(bucket, domain)
				break
			}
		}
	}
	return bucket
}
