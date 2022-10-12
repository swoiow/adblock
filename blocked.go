package blocked

import (
	"context"
	"time"

	"github.com/bits-and-blooms/bloom/v3"
	"github.com/coredns/coredns/plugin"
	"github.com/coredns/coredns/plugin/metrics"
	clog "github.com/coredns/coredns/plugin/pkg/log"
	"github.com/miekg/dns"
	"github.com/swoiow/dns_utils"
)

var log = clog.NewWithPlugin(pluginName)

func (app Blocked) ServeDNS(ctx context.Context, w dns.ResponseWriter, r *dns.Msg) (int, error) {
	question := r.Question[0]

	if fn, ok := app.Configs.blockQtype[question.Qtype]; ok {
		w.WriteMsg(fn(question, r))
		return dns.RcodeSuccess, nil
	} else if !(question.Qtype == dns.TypeA || question.Qtype == dns.TypeAAAA) {
		return plugin.NextOrFailure(pluginName, app.Next, ctx, w, r)
	}

	// measure time spent
	start := time.Now()

	// https://github.com/AdguardTeam/AdGuardDNS/blob/c2344850dabe23ce50d446b0f78d8a099fb03dfd/dnsfilter/dnsfilter.go#L156
	qDomain := dns_utils.PureDomain(question.Name)

	if dns_utils.IsHostname(qDomain) {
		if app.Configs.hostnameQ == IGNORE {
			return plugin.NextOrFailure(pluginName, app.Next, ctx, w, r)
		} else {
			w.WriteMsg(CreateREFUSED(question, r))
			return dns.RcodeSuccess, nil
		}
	}

	isBlock := IsBlocked(app.Configs, qDomain)

	if app.Configs.wildcardMode && !isBlock {
		dnList := dns_utils.GetWild(qDomain)
		// log.Infof("Wild list: %v", dnList)
		for _, dn := range dnList {
			if isBlock = IsBlocked(app.Configs, dn); isBlock {
				break
			}
		}
	}

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

func (app Blocked) reloadConfig() {
	log.Infof("[reload]: %s", time.Now())
	bFilter := bloom.NewWithEstimates(uint(app.Configs.Size), app.Configs.Rate)
	if app.Configs.cacheDataPath != "" {
		handleCacheData(app.Configs.cacheDataPath, bFilter)
	}

	if len(app.Configs.blackRules) > 0 {
		for _, rule := range app.Configs.blackRules {
			handleBlackRules(rule, bFilter)
		}
	}

	if len(app.Configs.whiteRules) > 0 {
		wFilter := bloom.NewWithEstimates(100_000, 0.001)
		for _, rule := range app.Configs.whiteRules {
			handleWhiteRules(rule, wFilter)
		}

		app.Configs.Lock()
		app.Configs.wFilter = wFilter
		app.Configs.Unlock()
	}

	app.Configs.Lock()
	app.Configs.filter = bFilter
	app.Configs.Unlock()
}

func (app Blocked) Name() string { return pluginName }

// ====== Plugin logic below ======

func IsBlocked(cfg *Configs, host string) bool {
	return !(cfg.wFilter != nil && cfg.wFilter.TestString(host)) && cfg.filter.TestString(host)
}
