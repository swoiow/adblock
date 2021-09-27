package adblock

import (
	"bufio"
	"github.com/bits-and-blooms/bloom/v3"
	"github.com/coredns/caddy"
	"io"
	"io/ioutil"
	"net/http"
	"os"
	"strings"
)

type Configs struct {
	Capacity float64
	Size     int

	filter bloom.BloomFilter
	log    bool
}

var DefaultConfigs = Configs{
	Size:     200_000,
	Capacity: 0.0001,

	log: false,
}

func parseConfiguration(c *caddy.Controller) (*Configs, error) {
	configs := DefaultConfigs
	filter := bloom.NewWithEstimates(uint(configs.Size), configs.Capacity)
	configs.filter = *filter

	for c.NextBlock() {
		value := c.Val()

		switch value {
		case "log":
			configs.log = true
			break
		case "cache-data": //TODO
			args := c.RemainingArgs()
			err := ReadData(strings.TrimSpace(args[0]), filter)

			if err != nil {
				return nil, err
			}
			break
		case "black-list":
			args := c.RemainingArgs()
			inputString := strings.TrimSpace(args[0])
			if strings.HasPrefix(strings.ToLower(inputString), "http://") ||
				strings.HasPrefix(strings.ToLower(inputString), "https://") {
				_ = LoadDataByRemote(inputString, filter)
			} else {
				_ = LoadDataByLocal(inputString, filter)
			}
			break
		case "}":
		case "{":
			break
		}
	}

	return &configs, nil
}

func LoadDataByLocal(path string, filter *bloom.BloomFilter) error {
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

func LoadDataByRemote(uri string, filter *bloom.BloomFilter) error {
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

	log.Info("Loaded rules:%v from `%s`.", counter, uri)
	return nil
}

func ReadData(path string, filter *bloom.BloomFilter) error {
	file, err := os.Open(path)
	if err != nil {
		return err
	}
	defer file.Close()

	_, err = filter.ReadFrom(file)
	if err != nil {
		return err
	}

	log.Infof("Loaded about %v rules from filter.", filter.K())
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
