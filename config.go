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

type Configs struct {
	Size int
	Rate float64

	filter   *bloom.BloomFilter
	log      bool
	respType string
}

var DefaultConfigs = &Configs{
	Size: 250_000,
	Rate: 0.0001,

	log:      false,
	respType: SOA,
}

func parseConfiguration(c *caddy.Controller) (*Configs, error) {
	configs := *DefaultConfigs
	filter := bloom.NewWithEstimates(uint(configs.Size), configs.Rate)
	configs.filter = filter

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
		case "resp_type":
			args := c.RemainingArgs()
			inputString := strings.TrimSpace(args[0])
			switch strings.ToUpper(inputString) {
			case ZERO:
				configs.respType = ZERO
				break
			case HINFO:
				configs.respType = HINFO
				break
			case NO_ANS:
				configs.respType = NO_ANS
				break
			}
			break
		case "cache-data":
			args := c.RemainingArgs()
			inputString := strings.TrimSpace(args[0])
			if strings.HasPrefix(strings.ToLower(inputString), "http://") ||
				strings.HasPrefix(strings.ToLower(inputString), "https://") {
				_ = LoadCacheByRemote(inputString, filter)
			} else {
				_ = LoadCacheByLocal(inputString, filter)
			}
			break
		case "black-list":
			args := c.RemainingArgs()
			inputString := strings.TrimSpace(args[0])
			if strings.HasPrefix(strings.ToLower(inputString), "http://") ||
				strings.HasPrefix(strings.ToLower(inputString), "https://") {
				_ = LoadRuleByRemote(inputString, filter)
			} else {
				_ = LoadRuleByLocal(inputString, filter)
			}
			break
		case "}":
		case "{":
			break
		}
	}

	return &configs, nil
}

func LoadRuleByLocal(path string, filter *bloom.BloomFilter) error {
	file, err := os.Open(path)
	if err != nil {
		log.Error(err)
		return err
	}
	defer file.Close()

	counter := 0
	reader := bufio.NewReader(file)
	contents, _ := ioutil.ReadAll(reader)

	lines := strings.Split(string(contents), string('\n'))
	for _, line := range lines {
		line = strings.TrimSpace(line)
		if strings.HasPrefix(line, "#") && len(line) > 0 {
			continue
		}
		if !filter.TestAndAddString(line) {
			counter += 1
		}
	}

	log.Infof("Loaded rules:%v from `%s`.", counter, path)
	return nil
}

func LoadRuleByRemote(uri string, filter *bloom.BloomFilter) error {
	lines, err := UrlToLines(uri)
	if err != nil {
		log.Error(err)
		return err
	}

	counter := 0
	for _, line := range lines {
		line = strings.TrimSpace(line)
		if strings.HasPrefix(line, "#") && len(line) > 0 {
			continue
		}
		if !filter.TestAndAddString(line) {
			counter += 1
		}
	}

	log.Infof("Loaded rules:%v from `%s`.", counter, uri)
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
	log.Infof("Loaded cache from `%s`.", uri)

	return nil
}

func LoadCacheByLocal(path string, filter *bloom.BloomFilter) error {
	file, err := os.Open(path)
	if err != nil {
		return err
	}
	defer file.Close()

	_, err = filter.ReadFrom(file)
	if err != nil {
		return err
	}

	log.Infof("Loaded cache from `%s`.", path)
	return nil
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
