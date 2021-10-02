package adblock

import (
	"bufio"
	"github.com/bits-and-blooms/bloom/v3"
	"github.com/coredns/caddy"
	"github.com/coredns/coredns/plugin"
	"io"
	"io/ioutil"
	"net/http"
	"os"
	"strconv"
	"strings"
)

var DefaultConfigs = &Configs{
	Size: 300_000,
	Rate: 0.01,

	log:        false,
	respType:   SOA,
	blockQtype: make(map[uint16]bool, 10),

	whiteListMode: false,
}

func parseConfiguration(c *caddy.Controller) (*Configs, error) {
	configs := *DefaultConfigs
	configs.filter = bloom.NewWithEstimates(uint(configs.Size), configs.Rate)

	for c.NextBlock() {
		value := c.Val()

		switch value {
		case "size_rate":
			args := c.RemainingArgs()
			switch len(args) {
			case 1:
				size, err := strconv.Atoi(args[0])
				if err != nil {
					return nil, plugin.Error(pluginName, c.Errf("pares size error: %s", err))
				}
				configs.Size = size
			case 2:
				rate, err := strconv.ParseFloat(args[1], 32)
				if err != nil {
					return nil, plugin.Error(pluginName, c.Errf("pares capacity error: %s", err))
				}
				configs.Rate = rate
			}
			break
		case "log":
			configs.log = true
			break
		case "block_qtype":
			args := c.RemainingArgs()
			for ix := 0; ix < len(args); ix++ {
				qtype := args[ix]
				if val, ok := blockQueryType[strings.ToUpper(qtype)]; ok {
					configs.blockQtype[val] = true
				}
			}
			break
		case "resp_type":
			args := c.RemainingArgs()
			inputString := strings.TrimSpace(args[0])
			if val, ok := respTypeEnum[strings.ToUpper(inputString)]; ok {
				configs.respType = val
			}
			break
		case "cache_data":
			args := c.RemainingArgs()
			inputString := strings.TrimSpace(args[0])
			if strings.HasPrefix(strings.ToLower(inputString), "http://") ||
				strings.HasPrefix(strings.ToLower(inputString), "https://") {
				_ = LoadCacheByRemote(inputString, configs.filter)
			} else {
				_ = LoadCacheByLocal(inputString, configs.filter)
			}
			break
		case "black_list":
			args := c.RemainingArgs()
			inputString := strings.TrimSpace(args[0])
			if strings.HasPrefix(strings.ToLower(inputString), "http://") ||
				strings.HasPrefix(strings.ToLower(inputString), "https://") {
				_ = LoadRuleByRemote(inputString, configs.filter)
			} else {
				_ = LoadRuleByLocal(inputString, configs.filter)
			}
			break
		case "white_list":
			args := c.RemainingArgs()
			inputString := strings.TrimSpace(args[0])
			var lines []string
			if strings.HasPrefix(strings.ToLower(inputString), "http://") ||
				strings.HasPrefix(strings.ToLower(inputString), "https://") {
				lines, _ = UrlToLines(inputString)
			} else {
				lines, _ = FileToLines(inputString)
			}

			if len(lines) > 0 {
				if !configs.whiteListMode {
					configs.whiteListMode = true
					configs.whiteList = bloom.NewWithEstimates(100_000, 0.01)
					log.Info("WhiteList mode is enabled")
				}
				addLines2filter(lines, configs.whiteList)
			}

			break
		case "}":
		case "{":
			break
		}
	}

	return &configs, nil
}

func addLines2filter(lines []string, filter *bloom.BloomFilter) (int, *bloom.BloomFilter) {
	c := 0
	for _, line := range lines {
		line = strings.ToLower(strings.TrimSpace(line))
		if strings.HasPrefix(line, "#") || len(line) <= 3 || len(line) > 64 {
			continue
		}
		if !filter.TestAndAddString(line) {
			c += 1
		}
	}
	return c, filter
}

func LoadRuleByLocal(path string, filter *bloom.BloomFilter) error {
	rf, err := os.Open(path)
	if err != nil {
		log.Error(err)
		return err
	}
	defer rf.Close()

	reader := bufio.NewReader(rf)
	contents, _ := ioutil.ReadAll(reader)
	lines := strings.Split(string(contents), string('\n'))
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
	log.Infof(loadLogFmt, "cache", "-", uri)

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

	log.Infof(loadLogFmt, "cache", "-", path)
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
