package adblock

import (
	"github.com/coredns/caddy"
	"github.com/coredns/coredns/core/dnsserver"
	"github.com/coredns/coredns/plugin"
)

func init() {
	plugin.Register(pluginName, setup)
	//caddy.RegisterPlugin(pluginName, caddy.Plugin{
	//	ServerType: "dns",
	//	Action:     setup,
	//})
}

func setup(c *caddy.Controller) error {
	c.Next()
	configs, err := parseConfiguration(c)

	if err != nil {
		return err
	}

	app := Adblock{}
	dnsserver.GetConfig(c).AddPlugin(func(next plugin.Handler) plugin.Handler {
		app.Next = next
		app.filter = configs.filter
		return &app
	})

	return nil
}
