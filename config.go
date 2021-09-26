package adblock

import (
	"bufio"
	"encoding/json"
	"fmt"
	"github.com/bits-and-blooms/bloom"
	"github.com/coredns/caddy"
	"io"
	"io/ioutil"
	"net/http"
	"os"
	"strings"
)

type ListMap map[string]bool

type Configs struct {
	filter   bloom.BloomFilter
	Capacity float64
	Size     int
}

var DefaultConfigs = Configs{
	Size:     500_000,
	Capacity: 0.0005,
}

func parseConfiguration(c *caddy.Controller) (*Configs, error) {
	configs := DefaultConfigs
	filter := bloom.NewWithEstimates(uint(configs.Size), configs.Capacity)
	configs.filter = *filter

	for c.NextBlock() {
		value := c.Val()
		switch value {
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

	reader := bufio.NewReader(file)
	contents, _ := ioutil.ReadAll(reader)
	lines := strings.Split(string(contents), string('\n'))

	for _, line := range lines {
		filter.TestAndAddString(line)
	}

	log.Info("finished load data from local!")
	return nil
}

func LoadDataByRemote(uri string, filter *bloom.BloomFilter) error {

	lines, err := UrlToLines(uri)
	if err != nil {
		log.Error(err)
		return err
	}

	for _, line := range lines {
		filter.TestAndAddString(line)
	}

	log.Info("finished load data from remote!")
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

	log.Info(fmt.Sprintf("Loaded about %v rules from filter.", filter.K()))
	return nil
}

func ReadRuleSet(path string) (ListMap, error) {
	file, err := os.OpenFile(path, os.O_RDONLY, 0666)
	if err != nil {
		return nil, err
	}
	defer file.Close()

	plan, err := ioutil.ReadAll(file)
	if err != nil {
		return nil, err
	}

	var data ListMap
	err = json.Unmarshal(plan, &data)
	if err != nil {
		return nil, err
	}

	return data, nil
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
