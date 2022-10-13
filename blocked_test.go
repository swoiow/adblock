package blocked

import (
	"context"
	"strings"
	"testing"

	"github.com/bits-and-blooms/bloom/v3"
	"github.com/coredns/coredns/plugin/pkg/dnstest"
	"github.com/coredns/coredns/plugin/test"
	"github.com/miekg/dns"
)

func TestBlackListOnly(t *testing.T) {
	// arrange
	host := "example.com"
	runCfg := NewConfigs()
	runCfg.filter = bloom.NewWithEstimates(uint(runCfg.Size), runCfg.Rate)
	addLines2filter([]string{host}, runCfg.filter)

	tests := []struct {
		host string
		want bool
	}{
		{host: "example." + host, want: false},

		{host: host, want: true},
		{host: strings.ToUpper(host), want: true},
		{host: host + ".", want: true},
	}
	for _, tt := range tests {
		t.Run(tt.host, func(t *testing.T) {
			if got := IsBlocked(runCfg, strings.ToLower(strings.TrimSuffix(tt.host, "."))); got != tt.want {
				t.Errorf("IsBlocked() = %v, want %v", got, tt.want)
			}
		})
	}
}

func TestBlackListWithWhiteList(t *testing.T) {
	// arrange
	host := "example.com"
	runCfg := NewConfigs()

	runCfg.filter = bloom.NewWithEstimates(uint(runCfg.Size), runCfg.Rate)
	addLines2filter([]string{host, "example." + host}, runCfg.filter)

	runCfg.wFilter = bloom.NewWithEstimates(uint(runCfg.Size), runCfg.Rate)
	addLines2filter([]string{host}, runCfg.wFilter)

	tests := []struct {
		host string
		want bool
	}{
		{host: host, want: false},
		{host: strings.ToUpper(host), want: false},
		{host: host + ".", want: false},

		{host: "example." + host, want: true},
	}
	for _, tt := range tests {
		t.Run(tt.host, func(t *testing.T) {
			if got := IsBlocked(runCfg, strings.ToLower(strings.TrimSuffix(tt.host, "."))); got != tt.want {
				t.Errorf("IsBlocked() = %v, want %v", got, tt.want)
			}
		})
	}
}

func TestBlocked_ServeDNS_A_NEXT_PLUGIN(t *testing.T) {
	req := new(dns.Msg)
	req.SetQuestion("example.com.", dns.TypeA)

	rtc := NewConfigs()
	rtc.filter = bloom.NewWithEstimates(100, 0.01)
	c := &Blocked{Configs: rtc}

	rec := dnstest.NewRecorder(&test.ResponseWriter{})
	_, err := c.ServeDNS(context.TODO(), rec, req)

	if !strings.Contains(err.Error(), "no next plugin found") {
		t.Errorf("assert failed")
	}
}

func TestBlocked_ServeDNS_A_blocked_with_SOA(t *testing.T) {
	req := new(dns.Msg)
	req.SetQuestion("example.com.", dns.TypeA)

	rtc := NewConfigs()
	rtc.respFunc = CreateSOA
	rtc.filter = bloom.NewWithEstimates(100, 0.01)
	rtc.filter.AddString("example.com")
	c := &Blocked{Configs: rtc}

	rec := dnstest.NewRecorder(&test.ResponseWriter{})
	_, err := c.ServeDNS(context.TODO(), rec, req)

	if err != nil {
		t.Errorf("Expected no error, but got %q", err)
	}

	if rec.Msg.Ns[0].Header().Rrtype != dns.TypeSOA {
		t.Errorf("assert failed")
	}
}

func TestBlocked_ServeDNS_A_wildcard_blocked_with_SOA(t *testing.T) {
	req := new(dns.Msg)
	req.SetQuestion("a.example.com.", dns.TypeA)

	rtc := NewConfigs()
	rtc.respFunc = CreateSOA
	rtc.wildcardMode = true
	rtc.filter = bloom.NewWithEstimates(100, 0.01)
	rtc.filter.AddString("*.example.com")
	c := &Blocked{Configs: rtc}

	rec := dnstest.NewRecorder(&test.ResponseWriter{})
	_, err := c.ServeDNS(context.TODO(), rec, req)

	if err != nil {
		t.Errorf("Expected no error, but got %q", err)
	}

	if rec.Msg.Ns[0].Header().Rrtype != dns.TypeSOA {
		t.Errorf("assert failed")
	}
}

func TestBlocked_ServeDNS_AAAA_SOA(t *testing.T) {
	req := new(dns.Msg)
	req.SetQuestion("example.com.", dns.TypeAAAA)

	rtc := NewConfigs()
	rtc.filter = bloom.NewWithEstimates(100, 0.01)
	rtc.blockQtype[dns.TypeAAAA] = CreateSOA
	c := &Blocked{Configs: rtc}

	rec := dnstest.NewRecorder(&test.ResponseWriter{})
	_, err := c.ServeDNS(context.TODO(), rec, req)

	if err != nil {
		t.Errorf("Expected no error, but got %q", err)
	}

	if rec.Msg.Ns[0].Header().Rrtype != dns.TypeSOA {
		t.Errorf("assert failed")
	}
}

func TestBlocked_ServeDNS_ANY_NameError_in_default(t *testing.T) {
	req := new(dns.Msg)
	req.SetQuestion("example.com.", dns.TypeANY)

	rtc := NewConfigs()
	rtc.filter = bloom.NewWithEstimates(100, 0.01)
	c := &Blocked{Configs: rtc}

	rec := dnstest.NewRecorder(&test.ResponseWriter{})
	_, err := c.ServeDNS(context.TODO(), rec, req)

	if err != nil {
		t.Errorf("Expected no error, but got %q", err)
	}

	if rec.Msg.Rcode != dns.RcodeNameError {
		t.Errorf("assert failed")
	}
}

func TestBlocked_ServeDNS_ANY_REFUSED(t *testing.T) {
	req := new(dns.Msg)
	req.SetQuestion("example.com.", dns.TypeANY)

	rtc := NewConfigs()
	rtc.filter = bloom.NewWithEstimates(100, 0.01)
	rtc.blockQtype[dns.TypeANY] = CreateREFUSED
	c := &Blocked{Configs: rtc}

	rec := dnstest.NewRecorder(&test.ResponseWriter{})
	_, err := c.ServeDNS(context.TODO(), rec, req)

	if err != nil {
		t.Errorf("Expected no error, but got %q", err)
	}

	if rec.Msg.Rcode != dns.RcodeRefused {
		t.Errorf("assert failed")
	}
}

func TestBlocked_ServeDNS_Hostname_query_REFUSED(t *testing.T) {
	req := new(dns.Msg)
	req.SetQuestion("example.", dns.TypeA)

	rtc := NewConfigs()
	rtc.filter = bloom.NewWithEstimates(100, 0.01)
	rtc.hostnameQ = REFUSED
	c := &Blocked{Configs: rtc}

	rec := dnstest.NewRecorder(&test.ResponseWriter{})
	_, err := c.ServeDNS(context.TODO(), rec, req)

	if err != nil {
		t.Errorf("Expected no error, but got %q", err)
	}

	if rec.Msg.Rcode != dns.RcodeRefused {
		t.Errorf("assert failed")
	}
}

func TestBlocked_ServeDNS_Hostname_query_IGNORE(t *testing.T) {
	req := new(dns.Msg)
	req.SetQuestion("example.", dns.TypeA)

	rtc := NewConfigs()
	rtc.filter = bloom.NewWithEstimates(100, 0.01)
	rtc.hostnameQ = IGNORE
	c := &Blocked{Configs: rtc}

	rec := dnstest.NewRecorder(&test.ResponseWriter{})
	_, err := c.ServeDNS(context.TODO(), rec, req)

	if !strings.Contains(err.Error(), "no next plugin found") {
		t.Errorf("assert failed")
	}
}

func TestBlocked_ServeDNS_HTTPS_CNAME_blocked_with_SOA(t *testing.T) {
	rtc := NewConfigs()
	rtc.interceptQtype[dns.TypeHTTPS] = true
	rtc.interceptQtype[dns.TypeCNAME] = true
	rtc.respFunc = CreateSOA
	rtc.filter = bloom.NewWithEstimates(100, 0.01)
	rtc.filter.AddString("example.com")
	c := &Blocked{Configs: rtc}

	for _, qt := range []uint16{dns.TypeHTTPS, dns.TypeCNAME} {
		req := new(dns.Msg)
		req.SetQuestion("example.com.", qt)
		rec := dnstest.NewRecorder(&test.ResponseWriter{})
		_, err := c.ServeDNS(context.TODO(), rec, req)

		if err != nil {
			t.Errorf("Expected no error, but got %q", err)
		}

		if rec.Msg.Ns[0].Header().Rrtype != dns.TypeSOA {
			t.Errorf("assert failed")
		}
	}

}
