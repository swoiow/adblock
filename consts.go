package blocked

import (
	"sync"
	"time"

	"github.com/bits-and-blooms/bloom/v3"
	"github.com/coredns/coredns/plugin"
	"github.com/miekg/dns"
)

type RespType int8
type RespFunc func(q dns.Question, r *dns.Msg) *dns.Msg

const (
	MINUTE = 60
	HOUR   = 60 * MINUTE
	DAY    = 24 * HOUR
)

const (
	/*
	 * respType: using by switch logic
	 */
	NoAns RespType = iota
	SOA
	HINFO
	ZERO
	NX
	REFUSED
	IGNORE
)

const (
	NXDOMAIN = NX

	qLogFmt    = "%s: '%s' - spent: %s"
	loadLogFmt = ">> loaded %s (num:%v) from `%s`."
)

const (
	domainMinLength = 3
	domainMaxLength = 63
)

func string2RespType(s string) RespType {
	// define: respType, using by configmap
	switch s {
	case "IGNORE":
		return IGNORE
	case "NO_ANS", "NO-ANS", "NOANS":
		return NoAns
	case "SOA":
		return SOA
	case "HINFO":
		return HINFO
	case "ZERO":
		return ZERO
	case "NX", "NXDOMAIN":
		return NX
	case "REFUSED":
		return REFUSED
	}

	panic("Unable to identify resp type: " + s)
}

func RespType2RespFunc(rt RespType) RespFunc {
	switch rt {
	case HINFO:
		return CreateHINFO
	case ZERO:
		return CreateZERO
	case REFUSED:
		return CreateREFUSED
	case NoAns:
		return CreateNOANS
	case NXDOMAIN:
		return CreateNXDOMAIN
	case SOA:
		return CreateSOA
	}
	return nil
}

type Blocked struct {
	Next    plugin.Handler
	Configs *Configs
}

type Configs struct {
	sync.RWMutex

	Size int
	Rate float64

	bootstrapResolvers []string

	// 需要检测是否屏蔽的DNS查询类型（dns query type）
	interceptQtype map[uint16]bool

	log          bool
	wildcardMode bool
	hostnameQ    RespType

	respFunc   RespFunc
	blockQtype map[uint16]RespFunc

	filter  *bloom.BloomFilter
	wFilter *bloom.BloomFilter

	cacheDataPath string
	whiteRules    []string
	blackRules    []string

	// options
	interval time.Duration
}
