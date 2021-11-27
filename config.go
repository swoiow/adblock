package blocked

import (
	"bufio"
	"io"
	"io/ioutil"
	"net/http"
	"os"
	"strconv"
	"strings"

	"github.com/bits-and-blooms/bloom/v3"
	"github.com/coredns/caddy"
	"github.com/coredns/coredns/plugin"
	clog "github.com/coredns/coredns/plugin/pkg/log"
	"github.com/miekg/dns"
	"github.com/swoiow/blocked/parsers"
)

func NewConfigs() *Configs {
	c := &Configs{
		Size: 250_000,
		Rate: 0.001,

		log:        false,
		hostnameQ:  REFUSED,
		respFunc:   CreateSOA,
		blockQtype: make(map[uint16]RespFunc, 10),

		wFilter: nil,

		wildcardMode: false,
	}

	c.blockQtype[dns.TypeANY] = CreateNXDOMAIN
	return c
}

func parseConfiguration(c *caddy.Controller) (*Configs, error) {
	configs := NewConfigs()
	configs.filter = bloom.NewWithEstimates(uint(configs.Size), configs.Rate)

	for c.Next() {
		value := c.Val()
		args := c.RemainingArgs()

		switch value {
		case "size_rate":
			switch len(args) {
			case 1:
				size, err := strconv.Atoi(args[0])
				if err != nil {
					return nil, plugin.Error(pluginName, c.Errf("pares size error: %s", err))
				}
				configs.Size = size
			case 2:
				size, err := strconv.Atoi(args[0])
				if err != nil {
					return nil, plugin.Error(pluginName, c.Errf("pares size error: %s", err))
				}
				configs.Size = size
				rate, err := strconv.ParseFloat(args[1], 32)
				if err != nil {
					return nil, plugin.Error(pluginName, c.Errf("pares capacity error: %s", err))
				}
				configs.Rate = rate
			}
			configs.filter = bloom.NewWithEstimates(uint(configs.Size), configs.Rate)
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
			log.Info("[Settings] wildcard mode is enabled")
			configs.wildcardMode = true
			break

		case "cache_data":
			inputString := strings.TrimSpace(args[0])
			if strings.HasPrefix(strings.ToLower(inputString), "http://") ||
				strings.HasPrefix(strings.ToLower(inputString), "https://") {
				_ = LoadCacheByRemote(inputString, configs.filter)
			} else {
				_ = LoadCacheByLocal(inputString, configs.filter)
			}
			break

		case "black_list":
			inputString := strings.TrimSpace(args[0])

			strictMode := true
			if strings.HasPrefix(strings.ToLower(inputString), "local+") {
				strictMode = false
				inputString = strings.TrimPrefix(inputString, "local+")
			}

			if strings.HasPrefix(strings.ToLower(inputString), "http://") ||
				strings.HasPrefix(strings.ToLower(inputString), "https://") {
				_ = LoadRuleByRemote(inputString, configs.filter)
			} else {
				_ = LoadRuleByLocal(inputString, configs.filter, strictMode)
			}
			break

		case "white_list":
			inputString := strings.TrimSpace(args[0])

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
				if configs.wFilter == nil {
					configs.wFilter = bloom.NewWithEstimates(100_000, 0.001)
					log.Info("[Settings] whiteList mode is enabled")
				}

				addLines2filter(parsers.LooseParser(lines, parsers.DomainParser, minLen), configs.wFilter)
			}
			break

		case "{", "}":
			break

		default:
			return nil, c.Errf("unknown property '%s'", c.Val())
		}
	}

	return configs, nil
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

func LoadRuleByLocal(path string, filter *bloom.BloomFilter, strictMode bool) error {
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

func LoadRuleByRemote(uri string, filter *bloom.BloomFilter) error {
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

func LoadCacheByRemote(uri string, filter *bloom.BloomFilter) error {
	resp, err := http.Get(uri)
	if err != nil {
		return err
	}
	defer resp.Body.Close()

	_, err = filter.ReadFrom(resp.Body)
	if err != nil {
		return err
	}
	clog.Infof(loadLogFmt, "cache", filter.ApproximatedSize(), uri)

	return nil
}

func LoadCacheByLocal(path string, filter *bloom.BloomFilter) error {
	rf, err := os.Open(path)
	if err != nil {
		return err
	}
	defer rf.Close()

	_, err = filter.ReadFrom(rf)
	if err != nil {
		return err
	}

	clog.Infof(loadLogFmt, "cache", filter.ApproximatedSize(), path)
	return nil
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
