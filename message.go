package blocked

import (
	"net"

	"github.com/miekg/dns"
)

func CreateSOA(q dns.Question, r *dns.Msg) *dns.Msg {
	/* https:github.com/DNSCrypt/dnscrypt-proxy/blob/master/dnscrypt-proxy/plugin_block_ipv6.go#L31
	 */

	m := new(dns.Msg)
	m.SetReply(r)
	m.Authoritative = false
	m.RecursionAvailable = true

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

	return m
}

func CreateHINFO(q dns.Question, r *dns.Msg) *dns.Msg {
	/* https://github.com/coredns/coredns/blob/master/plugin/any/any.go
	 * https://github.com/DNSCrypt/dnscrypt-proxy/blob/master/dnscrypt-proxy/plugin_block_ipv6.go#L31
	 */

	m := new(dns.Msg)
	m.SetReply(r)
	m.Authoritative = false
	m.RecursionAvailable = true

	hinfo := new(dns.HINFO)
	hinfo.Cpu = "query blocked"
	hinfo.Os = "add the domain to white list to avoid"

	hinfo.Hdr = dns.RR_Header{Name: q.Name, Ttl: HOUR, Class: dns.ClassINET, Rrtype: dns.TypeHINFO}
	m.Answer = []dns.RR{hinfo}

	return m
}

func CreateZERO(q dns.Question, r *dns.Msg) *dns.Msg {
	m := new(dns.Msg)
	m.SetReply(r)
	m.Authoritative = false
	m.RecursionAvailable = true

	if q.Qtype == dns.TypeA {
		respIpv4 := new(dns.A)
		respIpv4.Hdr = dns.RR_Header{Name: q.Name, Ttl: HOUR, Class: dns.ClassINET, Rrtype: dns.TypeA}
		respIpv4.A = net.IPv4zero
		m.Answer = []dns.RR{respIpv4}
	} else if q.Qtype == dns.TypeAAAA {
		respIpv6 := new(dns.AAAA)
		respIpv6.Hdr = dns.RR_Header{Name: q.Name, Ttl: HOUR, Class: dns.ClassINET, Rrtype: dns.TypeAAAA}
		respIpv6.AAAA = net.IPv6zero
		m.Answer = []dns.RR{respIpv6}
	} else {
		return CreateNXDOMAIN(q, r)
	}

	return m
}

func CreateREFUSED(_ dns.Question, r *dns.Msg) *dns.Msg {
	m := new(dns.Msg)
	m.SetReply(r)
	m.Authoritative = false
	m.RecursionAvailable = true

	m.Answer, m.Ns, m.Extra = nil, nil, nil
	m.Rcode = dns.RcodeRefused
	return m
}

func CreateNOANS(_ dns.Question, r *dns.Msg) *dns.Msg {
	m := new(dns.Msg)
	m.SetReply(r)
	m.Authoritative = false
	m.RecursionAvailable = true

	m.Answer, m.Ns, m.Extra = nil, nil, nil
	m.Rcode = dns.RcodeSuccess
	return m
}

func CreateNXDOMAIN(_ dns.Question, r *dns.Msg) *dns.Msg {
	m := new(dns.Msg)
	m.SetReply(r)
	m.Authoritative = false
	m.RecursionAvailable = true

	m.Answer, m.Ns, m.Extra = nil, nil, nil
	m.Rcode = dns.RcodeNameError
	return m
}
