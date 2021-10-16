package blocked

import (
	"github.com/bits-and-blooms/bloom/v3"
	"github.com/coredns/coredns/plugin"
	"github.com/miekg/dns"
)

type respType int

const (
	MINUTE = 60
	HOUR   = 60 * MINUTE
	DAY    = 24 * HOUR
)

const (
	/*
	 * respType: using by switch logic
	 */
	NO_ANS respType = iota
	SOA
	HINFO
	ZERO
	NX
	REFUSED
)
const NXDOMAIN = NX

const (
	qLogFmt    = "%s: '%s' - spent: %s"
	loadLogFmt = "Loaded %s (num:%v) from `%s`."
)

const (
	domainMinLength = 3
	domainMaxLength = 63
)

func stringToRespType(s string) respType {
	// define: respType, using by configmap
	switch s {
	case "NO_ANS":
		return NO_ANS
	case "SOA":
		return SOA
	case "HINFO":
		return HINFO
	case "ZERO":
		return ZERO
	case "NXDOMAIN":
	case "NX":
		return NX
	case "REFUSED":
		return REFUSED
	}

	panic("Unable to identify resp type: " + s)
}

type Blocked struct {
	Next    plugin.Handler
	Configs *Configs
}

type Configs struct {
	Size int
	Rate float64

	log        bool
	filter     *bloom.BloomFilter
	blockQtype map[uint16]bool

	respType int8
	respFunc func(q dns.Question, r *dns.Msg) *dns.Msg

	whiteListMode bool
	wFilter       *bloom.BloomFilter
}
