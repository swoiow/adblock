package blocked

import (
	"strconv"
	"strings"
	"time"

	"github.com/bits-and-blooms/bloom/v3"
	"github.com/coredns/caddy"
	"github.com/coredns/coredns/plugin"
	"github.com/miekg/dns"
	"github.com/swoiow/dns_utils/loader"
	"github.com/swoiow/dns_utils/parsers"
)

func NewConfigs() *Configs {
	c := &Configs{
		Size: 250_000,
		Rate: 0.001,

		interceptQtype: make(map[uint16]bool),

		log:        false,
		hostnameQ:  REFUSED,
		respFunc:   CreateSOA,
		blockQtype: make(map[uint16]RespFunc, 10),

		wFilter: nil,

		wildcardMode: false,

		cacheDataPath: "",
		whiteRules:    []string{},
		blackRules:    []string{},

		interval: time.Duration(5 * 24 * time.Hour),
	}

	c.blockQtype[dns.TypeANY] = CreateNXDOMAIN
	return c
}

func parseConfiguration(c *caddy.Controller) (Blocked, error) {
	runtimeConfig := Blocked{}
	configs := NewConfigs()
	configs.filter = bloom.NewWithEstimates(uint(configs.Size), configs.Rate)

	for c.Next() {
		value := c.Val()
		args := c.RemainingArgs()

		switch value {
		case "intercept", "check":
			var interceptQtype []string

			for ix := 0; ix < len(args); ix++ {
				qTypeStr := strings.ToUpper(args[ix])
				qType := dns.StringToType[qTypeStr]
				configs.interceptQtype[qType] = true
				interceptQtype = append(interceptQtype, qTypeStr)
			}
			log.Infof("[doing] intercept: %s", interceptQtype)
			break

		case "interval", "reload":
			if len(args) != 1 {
				return runtimeConfig, c.Errf("reload needs a duration (zero seconds to disable)")
			}

			interval, err := time.ParseDuration(args[0])
			if err != nil || interval < 0 {
				return runtimeConfig, plugin.Error(pluginName, c.Errf("pares size error: %s", err))
			}
			configs.interval = interval
			log.Info("[doing] reload is enabled")
			break

		case "size_rate":
			switch len(args) {
			case 1:
				size, err := strconv.Atoi(args[0])
				if err != nil {
					return runtimeConfig, plugin.Error(pluginName, c.Errf("pares size error: %s", err))
				}
				configs.Size = size
			case 2:
				size, err := strconv.Atoi(args[0])
				if err != nil {
					return runtimeConfig, plugin.Error(pluginName, c.Errf("pares size error: %s", err))
				}
				configs.Size = size
				rate, err := strconv.ParseFloat(args[1], 32)
				if err != nil {
					return runtimeConfig, plugin.Error(pluginName, c.Errf("pares capacity error: %s", err))
				}
				configs.Rate = rate
			}
			configs.filter = bloom.NewWithEstimates(uint(configs.Size), configs.Rate)
			break

		case "log":
			configs.log = true
			log.Info("[doing] log is enabled")
			break

		case "hostname_query":
			inputString := "REFUSED"
			if len(args) > 0 {
				inputString = strings.ToUpper(strings.TrimSpace(args[0]))
			}

			switch string2RespType(inputString) {
			case REFUSED:
				configs.hostnameQ = REFUSED
			case IGNORE:
				configs.hostnameQ = IGNORE
			}
			log.Infof("[doing] hostname_query: %s", inputString)
			break

		case "resp_type":
			inputString := "SOA"
			if len(args) > 0 {
				inputString = strings.ToUpper(strings.TrimSpace(args[0]))
			}
			fn := RespType2RespFunc(string2RespType(inputString))
			if fn != nil {
				log.Infof("[doing] resp_type: %s", inputString)
				configs.respFunc = fn
			}

			// handle block_qtype config
			for c.NextBlock() {
				var blockQtype []string

				inputString = strings.ToUpper(strings.TrimSpace(c.Val()))
				blockMode := string2RespType(inputString)
				fn := RespType2RespFunc(blockMode)
				if fn != nil {
					qTypeArgs := c.RemainingArgs()
					for ix := 0; ix < len(qTypeArgs); ix++ {
						qTypeStr := strings.ToUpper(qTypeArgs[ix])
						qType := dns.StringToType[qTypeStr]
						configs.blockQtype[qType] = fn
						blockQtype = append(blockQtype, qTypeStr)
					}
				}
				if len(blockQtype) > 0 {
					log.Infof("[doing] block_qtype: %s -> %s", blockQtype, inputString)
				}
			}
			break

		case "wildcard":
			configs.wildcardMode = true
			log.Info("[doing] wildcard mode is enabled")
			break

		case "cache_data":
			if configs.cacheDataPath != "" {
				return runtimeConfig, plugin.Error(pluginName, c.Err("multi cache_data detect"))
			}

			inputString := strings.TrimSpace(args[0])
			originStr := inputString
			handleCacheData(inputString, configs.filter)
			configs.cacheDataPath = originStr
			break

		case "black_list":
			inputString := strings.TrimSpace(args[0])
			originStr := inputString
			handleBlackRules(inputString, configs.filter)
			configs.blackRules = append(configs.blackRules, originStr)
			break

		case "white_list":
			inputString := strings.TrimSpace(args[0])
			originStr := inputString
			configs.wFilter = bloom.NewWithEstimates(100_000, 0.001)
			handleWhiteRules(inputString, configs.wFilter)
			configs.whiteRules = append(configs.whiteRules, originStr)
			break

		case "{", "}":
			break

		default:
			return runtimeConfig, c.Errf("unknown property '%s'", c.Val())
		}
	}

	if len(configs.interceptQtype) == 0 {
		defaultQueryType := []string{"A", "AAAA", "CNAME", "HTTPS"}
		for _, qtStr := range defaultQueryType {
			configs.interceptQtype[dns.StringToType[qtStr]] = true
		}
		log.Infof("[doing] default intercept: %s", defaultQueryType)
	}

	runtimeConfig.Configs = configs
	return runtimeConfig, nil
}

func handleCacheData(inputString string, filter *bloom.BloomFilter) {
	m := loader.DetectMethods(inputString)
	err := m.LoadCache(filter)
	if err != nil {
		log.Warningf("handleCacheData with err: %s", err)
		return
	}
}

func handleBlackRules(inputString string, filter *bloom.BloomFilter) {
	m := loader.DetectMethods(inputString)
	m.StrictMode = !strings.HasPrefix(strings.ToLower(inputString), "local+")

	lines, err := m.LoadRules(m.StrictMode)
	if err != nil {
		log.Warningf("handleBlackRules with err: %s", err)
		return
	}

	addLines2filter(lines, filter)
}

func handleWhiteRules(inputString string, wFilter *bloom.BloomFilter) {
	minLen := domainMinLength
	m := loader.DetectMethods(inputString)
	if m.IsRules {
		minLen = 1
	}

	lines, err := m.LoadRules(m.StrictMode)
	if err != nil {
		log.Warningf("handleWhiteRules with err: %s", err)
		return
	}

	if wFilter == nil {
		wFilter = bloom.NewWithEstimates(100_000, 0.001)
		log.Info("[doing] whiteList mode is enabled")
	}

	addLines2filter(parsers.LooseParser(lines, parsers.DomainParser, minLen), wFilter)
}

/*
 *   Utils
 */

func addLines2filter(lines []string, filter *bloom.BloomFilter) (int, *bloom.BloomFilter) {
	c := 0
	for _, line := range lines {
		if !filter.TestAndAddString(strings.ToLower(strings.TrimSpace(line))) {
			c += 1
		}
	}
	return c, filter
}
