package parsers

var engines = []func(s string) []string{
	HostParser,
	SurgeParser,
	DnsmasqParser,
	DomainParser,
}

func Parse(line string, engine func(s string) []string) (bool, []string) {
	if IsCommentOrEmptyLine(line) {
		return false, nil
	}

	var bucket []string
	domains := engine(line)
	for _, domain := range domains {
		if IsDomainName(domain) {
			bucket = append(bucket, domain)
		}
		// to debug
		// fmt.Printf("Handle domain: `%s` failed after parse.\n", domain)
	}

	if len(bucket) > 0 {
		return true, bucket
	} else {
		return false, nil
	}
}

func LooseParser(lines []string, engine func(d string) []string, minLen int) []string {
	var bucket []string

	for _, line := range lines {
		if !IsDomainNamePlus(line, minLen, false, false) {
			continue
		}
		domains := engine(line)
		bucket = append(bucket, domains...)
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
			result, domains := Parse(line, engine)
			if result {
				for _, domain := range domains {
					result = IsDomainNamePlus(domain, minLen, true, true)
					if result {
						// fmt.Printf("line: `%s` parsered by: %s\n", line, getFunctionName(engine))
						bucket = append(bucket, domain)
					}
				}
				break
			}
		}
	}
	return bucket
}
