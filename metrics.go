package adblock

import (
	"github.com/coredns/coredns/plugin"

	"github.com/prometheus/client_golang/prometheus"
	"github.com/prometheus/client_golang/prometheus/promauto"
)

var (
	hintedCount = promauto.NewCounterVec(prometheus.CounterOpts{
		Namespace: plugin.Namespace,
		Subsystem: pluginName,
		Name:      pluginName + "_hinted_total",
		Help:      "Counter hinted rules",
	}, []string{"server"})
	missesCount = promauto.NewCounterVec(prometheus.CounterOpts{
		Namespace: plugin.Namespace,
		Subsystem: pluginName,
		Name:      pluginName + "_misses_total",
		Help:      "Counter not hinted rules",
	}, []string{"server"})
)
