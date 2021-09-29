package adblock

import (
	"github.com/bits-and-blooms/bloom/v3"
	"github.com/coredns/coredns/plugin"
	"github.com/miekg/dns"
)

const (
	NO_ANS = "NO-ANS"
	SOA    = "SOA"
	HINFO  = "HINFO"
	ZERO   = "ZERO"

	MINUTE = 60
	HOUR   = 60 * MINUTE
	DAY    = 24 * HOUR
)

type Adblock struct {
	Next    plugin.Handler
	Configs *Configs
}

type Configs struct {
	Size int
	Rate float64

	log        bool
	filter     *bloom.BloomFilter
	whiteList  map[string]bool
	respType   string
	blockQtype map[uint16]bool
}

var blockQueryType = map[string]uint16{
	"A":     dns.TypeA,
	"AAAA":  dns.TypeAAAA,
	"MX":    dns.TypeMX,
	"HTTPS": dns.TypeHTTPS,
	"PTR":   dns.TypePTR,
	"SRV":   dns.TypeSRV,
	"CNAME": dns.TypeCNAME,
}
