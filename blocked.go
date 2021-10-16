package blocked

import (
	"context"
	"strings"
	"time"

	"github.com/coredns/coredns/plugin"
	"github.com/coredns/coredns/plugin/metrics"
	clog "github.com/coredns/coredns/plugin/pkg/log"
	"github.com/miekg/dns"
)

var log = clog.NewWithPlugin(pluginName)

func (app Blocked) ServeDNS(ctx context.Context, w dns.ResponseWriter, r *dns.Msg) (int, error) {
	question := r.Question[0]

	if app.Configs.blockQtype[question.Qtype] {
		w.WriteMsg(CreateREFUSED(question, r))
		return dns.RcodeSuccess, nil
	} else if question.Qtype != dns.TypeA && question.Qtype != dns.TypeAAAA {
		return plugin.NextOrFailure(pluginName, app.Next, ctx, w, r)
	}

	// measure time spent
	start := time.Now()

	// https://github.com/AdguardTeam/AdGuardDNS/blob/c2344850dabe23ce50d446b0f78d8a099fb03dfd/dnsfilter/dnsfilter.go#L156
	qDomain := strings.ToLower(strings.TrimSuffix(question.Name, "."))
	isBlock := IsBlocked(app.Configs, qDomain)

	if isBlock {
		w.WriteMsg(app.Configs.respFunc(question, r))
		if app.Configs.log {
			log.Infof(qLogFmt, "hinted", qDomain, time.Since(start))
		}
		hintedCount.WithLabelValues(metrics.WithServer(ctx)).Inc()
		return dns.RcodeSuccess, nil
	} else {
		if app.Configs.log {
			log.Infof(qLogFmt, "not hint", qDomain, time.Since(start))
		}
		missesCount.WithLabelValues(metrics.WithServer(ctx)).Inc()
		return plugin.NextOrFailure(pluginName, app.Next, ctx, w, r)
	}
}

func (app Blocked) Name() string { return pluginName }

// ====== Plugin logic below ======

func IsBlocked(cfg *Configs, host string) bool {
	return !(cfg.whiteListMode && cfg.wFilter.TestString(host)) && cfg.filter.TestString(host)
}
