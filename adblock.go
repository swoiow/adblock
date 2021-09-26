package adblock

import (
	"context"
	"fmt"
	"github.com/bits-and-blooms/bloom"
	"github.com/coredns/coredns/plugin"
	clog "github.com/coredns/coredns/plugin/pkg/log"
	"github.com/miekg/dns"
	"strings"
)

var log = clog.NewWithPlugin(pluginName)

const (
	SOA = "SOA"
)

type Adblock struct {
	Next    plugin.Handler
	ResType string

	filter bloom.BloomFilter
	log    bool
}

func (app Adblock) ServeDNS(ctx context.Context, w dns.ResponseWriter, r *dns.Msg) (int, error) {
	// measure time spent
	//start := time.Now()

	// https://github.com/AdguardTeam/AdGuardDNS/blob/c2344850dabe23ce50d446b0f78d8a099fb03dfd/dnsfilter/dnsfilter.go#L156
	question := r.Question[0]
	host := strings.ToLower(strings.TrimSuffix(question.Name, "."))

	isBlock := handle(app, host, w, r)
	//log.Info("query block at: ", time.Since(start).Seconds())

	if isBlock {
		return dns.RcodeSuccess, nil
	} else {
		return plugin.NextOrFailure(pluginName, app.Next, ctx, w, r)
	}
}

func (app Adblock) Name() string { return pluginName }

// ====== Plugin logic below

// if host in black list turn true else return false
func handle(app Adblock, host string, w dns.ResponseWriter, r *dns.Msg) bool {
	if !app.filter.TestString(host) {
		if app.log {
			log.Info(fmt.Sprintf("not hint: '%v'", host))
		}
		return false
	}

	if app.log {
		log.Info(fmt.Sprintf("hinted: '%v'", host))
	}

	m := new(dns.Msg)
	m.SetReply(r)
	m.Authoritative = false
	m.RecursionAvailable = true

	result := SOA // TODO: plugin can set response type
	m.Answer, m.Ns, m.Extra = nil, nil, nil

	switch result {
	case SOA:
		m.Rcode = dns.RcodeNameError
	}

	w.WriteMsg(m)
	return true
}
