package adblock

import (
	"context"
	"github.com/coredns/coredns/plugin"
	clog "github.com/coredns/coredns/plugin/pkg/log"
	"github.com/miekg/dns"
	"net"
	"strings"
)

var log = clog.NewWithPlugin(pluginName)

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
	Next plugin.Handler

	Configs *Configs
}

func (app Adblock) ServeDNS(ctx context.Context, w dns.ResponseWriter, r *dns.Msg) (int, error) {
	question := r.Question[0]

	if question.Qtype != dns.TypeA && question.Qtype != dns.TypeAAAA {
		return plugin.NextOrFailure(pluginName, app.Next, ctx, w, r)
	}

	// measure time spent
	//start := time.Now()

	// https://github.com/AdguardTeam/AdGuardDNS/blob/c2344850dabe23ce50d446b0f78d8a099fb03dfd/dnsfilter/dnsfilter.go#L156
	host := strings.ToLower(strings.TrimSuffix(question.Name, "."))

	isBlock := handle(app, host, question, w, r)
	//log.Info("query block at: ", time.Since(start).Seconds())

	if isBlock {
		return dns.RcodeSuccess, nil
	} else {
		return plugin.NextOrFailure(pluginName, app.Next, ctx, w, r)
	}
}

func (app Adblock) Name() string { return pluginName }

// ====== Plugin logic below

// if host in black list return true else return false
func handle(app Adblock, host string, q dns.Question, w dns.ResponseWriter, r *dns.Msg) bool {
	if !app.Configs.filter.TestString(host) {
		if app.Configs.log {
			log.Infof("not hint: '%s'", host)
		}
		return false
	}

	if app.Configs.log {
		log.Infof("hinted: '%s'", host)
	}

	m := new(dns.Msg)
	m.SetReply(r)
	m.Authoritative = false
	m.RecursionAvailable = true

	switch app.Configs.respType {
	case SOA:
		/* https://github.com/DNSCrypt/dnscrypt-proxy/blob/master/dnscrypt-proxy/plugin_block_ipv6.go#L31
		 */
		soa := new(dns.SOA)
		soa.Mbox = "query.blocked."
		soa.Ns = "a.root-servers.net."
		soa.Serial = 1
		soa.Refresh = DAY
		soa.Minttl = HOUR
		soa.Expire = DAY
		soa.Retry = 300

		headers := dns.RR_Header{Name: q.Name, Ttl: HOUR, Class: dns.ClassINET, Rrtype: dns.TypeSOA}
		soa.Hdr = headers
		m.Ns = []dns.RR{soa}
		break

	case HINFO:
		/* https://github.com/coredns/coredns/blob/master/plugin/any/any.go
		 * https://github.com/DNSCrypt/dnscrypt-proxy/blob/master/dnscrypt-proxy/plugin_block_ipv6.go#L31
		 */
		hinfo := new(dns.HINFO)
		hinfo.Cpu = "query blocked"
		hinfo.Os = "add the domain to white list to avoid"

		hinfo.Hdr = dns.RR_Header{Name: q.Name, Ttl: HOUR, Class: dns.ClassINET, Rrtype: dns.TypeHINFO}
		m.Answer = []dns.RR{hinfo}
		break

	case ZERO:
		switch q.Qtype {
		case dns.TypeA:
			respIpv4 := new(dns.A)
			respIpv4.Hdr = dns.RR_Header{Name: q.Name, Ttl: HOUR, Class: dns.ClassINET, Rrtype: dns.TypeA}
			respIpv4.A = net.IPv4zero
			m.Answer = []dns.RR{respIpv4}
		case dns.TypeAAAA:
			respIpv6 := new(dns.AAAA)
			respIpv6.Hdr = dns.RR_Header{Name: q.Name, Ttl: HOUR, Class: dns.ClassINET, Rrtype: dns.TypeAAAA}
			respIpv6.AAAA = net.IPv6zero
			m.Answer = []dns.RR{respIpv6}
		}
		break

	case NO_ANS:
	default:
		/* no ANSWER is default
		 */
		m.Answer, m.Ns, m.Extra = nil, nil, nil
		m.Rcode = dns.RcodeNameError
		break
	}

	err := w.WriteMsg(m)
	if err != nil {
		log.Error(err)
		return false
	}
	return true
}
