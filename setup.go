package blocked

import (
	"fmt"
	"time"

	"github.com/coredns/caddy"
	"github.com/coredns/coredns/core/dnsserver"
	"github.com/coredns/coredns/plugin"
)

func init() {
	plugin.Register(pluginName, setup)
}

func periodicConfigUpdate(b *Blocked) chan bool {
	c := make(chan bool)

	if b.Configs.interval == 0 {
		return c
	}

	go func() {
		ticker := time.NewTicker(b.Configs.interval)
		fmt.Println("")
		for {
			select {
			case <-c:
				return
			case <-ticker.C:
				b.reloadConfig()
			}
		}
	}()

	return c
}

func setup(c *caddy.Controller) error {
	log.Infof("Initializing, %s: v%s", pluginName, pluginVer)
	c.Next() // unknown error in Corefile parse config - Error during parsing: unknown property 'blocked'
	app, err := parseConfiguration(c)
	if err != nil {
		return err
	}

	// OnStartup
	parseChan := periodicConfigUpdate(&app)
	// OnShutdown
	c.OnShutdown(func() error {
		close(parseChan)
		return nil
	})

	// app := Blocked{Configs: runtimeConfigs}
	dnsserver.GetConfig(c).AddPlugin(func(next plugin.Handler) plugin.Handler {
		app.Next = next
		return &app
	})

	fmt.Printf("\n")
	return nil
}
