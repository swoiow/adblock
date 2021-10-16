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
	"github.com/miekg/dns"
	"github.com/swoiow/blocked/parsers"
)

func DefaultConfigs() *Configs {
	return &Configs{
		Size: 300_000,
		Rate: 0.01,

		log:        false,
		respType:   int8(SOA),
		blockQtype: make(map[uint16]bool, 10),

		whiteListMode: false,
	}
}

func parseConfiguration(c *caddy.Controller) (*Configs, error) {
	configs := *DefaultConfigs()
	configs.filter = bloom.NewWithEstimates(uint(configs.Size), configs.Rate)

	for c.NextBlock() {
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
			break

		case "log":
			configs.log = true
			log.Info("[runtimeConfigs] log is enabled")
			break

		case "block_qtype":
			var blockQtype []string
			for ix := 0; ix < len(args); ix++ {
				qtype := strings.ToUpper(args[ix])
				val := dns.StringToType[qtype]
				if val != 0 {
					configs.blockQtype[val] = true
					blockQtype = append(blockQtype, qtype)
				}
			}
			log.Infof("[runtimeConfigs] block_qtype: %s", blockQtype)
			break

		case "resp_type":
			var inputString string
			if args == nil {
				inputString = "SOA"
			} else {
				inputString = strings.ToUpper(strings.TrimSpace(args[0]))
			}

			switch stringToRespType(inputString) {
			case SOA:
				configs.respFunc = CreateSOA
				break
			case HINFO:
				configs.respFunc = CreateHINFO
				break
			case ZERO:
				configs.respFunc = CreateZERO
				break
			case REFUSED:
				configs.respFunc = CreateREFUSED
				break
			case NO_ANS:
				configs.respFunc = CreateNOANS
				break
			case NXDOMAIN:
				configs.respFunc = CreateNXDOMAIN
				break
			}

			log.Infof("[runtimeConfigs] resp_type: %s", inputString)
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
				if !configs.whiteListMode {
					configs.whiteListMode = true
					configs.wFilter = bloom.NewWithEstimates(100_000, 0.01)
					log.Info("[runtimeConfigs] WhiteList mode is enabled")
				}

				addLines2filter(parsers.LooseParser(lines, parsers.DomainParser, minLen), configs.wFilter)
			}
			break
		}
	}

	return &configs, nil
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

	log.Infof(loadLogFmt, "rules", c, path)
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
	log.Infof(loadLogFmt, "rules", c, uri)
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
	log.Infof(loadLogFmt, "cache", filter.ApproximatedSize(), uri)

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

	log.Infof(loadLogFmt, "cache", filter.ApproximatedSize(), path)
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
