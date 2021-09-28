package adblock

import (
	"github.com/coredns/caddy"
	"github.com/coredns/coredns/core/dnsserver"
	"github.com/coredns/coredns/plugin"
)

func init() {
	plugin.Register(pluginName, setup)
}

func setup(c *caddy.Controller) error {
	c.Next()
	runtimeConfigs, err := parseConfiguration(c)
	if err != nil {
		return err
	}

	app := Adblock{Configs: runtimeConfigs}
	dnsserver.GetConfig(c).AddPlugin(func(next plugin.Handler) plugin.Handler {
		app.Next = next
		return &app
	})

	return nil
}
