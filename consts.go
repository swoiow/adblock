package adblock

import (
	"github.com/bits-and-blooms/bloom/v3"
	"github.com/coredns/coredns/plugin"
	"github.com/miekg/dns"
)

const (
	MINUTE = 60
	HOUR   = 60 * MINUTE
	DAY    = 24 * HOUR

	/*
	 * respType: using by switch logic
	 */
	NO_ANS  = 1
	SOA     = 2
	HINFO   = 3
	ZERO    = 4
	NX      = 5
	REFUSED = 6
)

const (
	qLogFmt    = "%s: '%s' - spent: %s"
	loadLogFmt = "Loaded %s(%v) from `%s`."
)

// define: respType, using by configmap
var respTypeEnum = map[string]int8{
	"NO_ANS":  1,
	"SOA":     2,
	"HINFO":   3,
	"ZERO":    4,
	"NX":      5, // Non-Existent Domain
	"REFUSED": 6, // Query Refused
}

// define: blockQtype
var blockQueryType = map[string]uint16{
	"A":     dns.TypeA,
	"AAAA":  dns.TypeAAAA,
	"MX":    dns.TypeMX,
	"HTTPS": dns.TypeHTTPS,
	"PTR":   dns.TypePTR,
	"SRV":   dns.TypeSRV,
	"CNAME": dns.TypeCNAME,
}

type Adblock struct {
	Next    plugin.Handler
	Configs *Configs
}

type Configs struct {
	Size int
	Rate float64

	log        bool
	filter     *bloom.BloomFilter
	respType   int8
	blockQtype map[uint16]bool

	whiteListMode bool
	whiteList     *bloom.BloomFilter
}
