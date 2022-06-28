package blocked

import (
	"bufio"
	"io"
	"io/ioutil"
	"net/http"
	"os"
	"strconv"
	"strings"
	"time"

	"github.com/coredns/caddy"
	"github.com/coredns/coredns/plugin"
	clog "github.com/coredns/coredns/plugin/pkg/log"
	"github.com/miekg/dns"
	bloom "github.com/seiflotfy/cuckoofilter"
	"github.com/swoiow/blocked/parsers"
)

func NewConfigs() *Configs {
	c := &Configs{
		Size: 500_000,
		Rate: 0.001,

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
	configs.filter = bloom.NewFilter(uint(configs.Size))

	for c.Next() {
		value := c.Val()
		args := c.RemainingArgs()

		switch value {
		case "interval", "reload":
			if len(args) != 1 {
				return runtimeConfig, c.Errf("reload needs a duration (zero seconds to disable)")
			}

			interval, err := time.ParseDuration(args[0])
			if err != nil || interval < 0 {
				return runtimeConfig, plugin.Error(pluginName, c.Errf("pares size error: %s", err))
			}
			configs.interval = interval
			log.Info("[Settings] reload is enabled")
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
			configs.filter = bloom.NewFilter(uint(configs.Size))
			break

		case "log":
			configs.log = true
			log.Info("[Settings] log is enabled")
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
			log.Infof("[Settings] hostname_query: %s", inputString)
			break

		case "resp_type":
			inputString := "SOA"
			if len(args) > 0 {
				inputString = strings.ToUpper(strings.TrimSpace(args[0]))
			}
			fn := RespType2RespFunc(string2RespType(inputString))
			if fn != nil {
				log.Infof("[Settings] resp_type: %s", inputString)
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
					log.Infof("[Settings] block_qtype: %s -> %s", blockQtype, inputString)
				}
			}
			break

		case "wildcard":
			configs.wildcardMode = true
			log.Info("[Settings] wildcard mode is enabled")
			break

		case "cache_data":
			if configs.cacheDataPath != "" {
				return runtimeConfig, plugin.Error(pluginName, c.Err("multi cache_data detect"))
			}

			inputString := strings.TrimSpace(args[0])
			originStr := inputString
			configs.filter = handleCacheData(inputString)
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
			configs.wFilter = bloom.NewFilter(100_000)
			handleWhiteRules(inputString, configs.wFilter)
			configs.whiteRules = append(configs.whiteRules, originStr)
			break

		case "{", "}":
			break

		default:
			return runtimeConfig, c.Errf("unknown property '%s'", c.Val())
		}
	}

	runtimeConfig.Configs = configs
	return runtimeConfig, nil
}

func handleCacheData(inputString string) (filter *bloom.Filter) {
	if strings.HasPrefix(strings.ToLower(inputString), "http://") ||
		strings.HasPrefix(strings.ToLower(inputString), "https://") {
		filter, _ = RemoteCacheLoader(inputString)
	} else {
		filter, _ = LocalCacheLoader(inputString)
	}
	return filter
}

func handleBlackRules(inputString string, filter *bloom.Filter) {
	strictMode := true
	if strings.HasPrefix(strings.ToLower(inputString), "local+") {
		strictMode = false
		inputString = strings.TrimPrefix(inputString, "local+")
	}

	if strings.HasPrefix(strings.ToLower(inputString), "http://") ||
		strings.HasPrefix(strings.ToLower(inputString), "https://") {
		_ = RemoteRuleLoader(inputString, filter)
	} else {
		_ = LocalRuleLoader(inputString, filter, strictMode)
	}
}

func handleWhiteRules(inputString string, wFilter *bloom.Filter) {
	minLen := domainMinLength
	var lines []string
	if strings.HasPrefix(strings.ToLower(inputString), "http://") ||
		strings.HasPrefix(strings.ToLower(inputString), "https://") {
		lines, _ = UrlToLines(inputString)
	} else {
		lines, _ = FileToLines(inputString)
		minLen = 1
	}

	if len(lines) > 0 {
		log.Info("[Settings] whiteList mode is enabled")
		addLines2filter(parsers.LooseParser(lines, parsers.DomainParser, minLen), wFilter)
	}
}

/*
 *   Utils
 */

func addLines2filter(lines []string, filter *bloom.Filter) (int, *bloom.Filter) {
	c := 0
	for _, line := range lines {
		if !filter.InsertUnique([]byte(strings.ToLower(strings.TrimSpace(line)))) {
			c += 1
		}
	}
	return c, filter
}

func FileToLines(path string) ([]string, error) {
	rf, err := os.Open(path)
	if err != nil {
		return nil, err
	}
	defer rf.Close()
	return LinesFromReader(rf)
}

func UrlToLines(url string) ([]string, error) {
	resp, err := http.Get(url)
	if err != nil {
		return nil, err
	}
	defer resp.Body.Close()
	return LinesFromReader(resp.Body)
}

func LinesFromReader(r io.Reader) ([]string, error) {
	var lines []string
	scanner := bufio.NewScanner(r)
	for scanner.Scan() {
		lines = append(lines, scanner.Text())
	}
	if err := scanner.Err(); err != nil {
		return nil, err
	}

	return lines, nil
}

func LocalRuleLoader(path string, filter *bloom.Filter, strictMode bool) error {
	rf, err := os.Open(path)
	if err != nil {
		log.Error(err)
		return err
	}
	defer rf.Close()

	reader := bufio.NewReader(rf)
	contents, _ := ioutil.ReadAll(reader)
	lines := strings.Split(string(contents), string('\n'))

	if strictMode {
		lines = parsers.FuzzyParser(lines, 1)
	} else {
		lines = parsers.LooseParser(lines, parsers.DomainParser, 1)
	}
	c, _ := addLines2filter(lines, filter)

	clog.Infof(loadLogFmt, "rules", c, path)
	return nil
}

func LocalCacheLoader(path string) (*bloom.Filter, error) {
	rf, err := os.Open(path)
	if err != nil {
		return nil, err
	}
	defer rf.Close()

	data, err := ioutil.ReadAll(rf)
	filter, err := bloom.Decode(data)
	if err != nil {
		return nil, err
	}

	clog.Infof(loadLogFmt, "cache", filter.Count(), path)
	return filter, nil
}

func RemoteRuleLoader(uri string, filter *bloom.Filter) error {
	lines, err := UrlToLines(uri)
	if err != nil {
		log.Error(err)
		return err
	}

	// handle by parsers
	lines = parsers.FuzzyParser(lines, domainMinLength)
	c, _ := addLines2filter(lines, filter)
	clog.Infof(loadLogFmt, "rules", c, uri)
	return nil
}

func RemoteCacheLoader(uri string) (*bloom.Filter, error) {
	resp, err := http.Get(uri)
	if err != nil {
		return nil, err
	}
	defer resp.Body.Close()

	data, err := ioutil.ReadAll(resp.Body)
	filter, err := bloom.Decode(data)
	if err != nil {
		return nil, err
	}
	clog.Infof(loadLogFmt, "cache", filter.Count(), uri)

	return filter, nil
}
