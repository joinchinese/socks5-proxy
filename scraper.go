package main

import (
	"fmt"
	"io"
	"log"
	"net/http"
	"regexp"
	"strings"
)

// 同时兼容带 socks5:// 前缀和纯文本 IP:Port 格式
var (
	socks5PrefixRegex = regexp.MustCompile(`socks5://(\d{1,3}\.\d{1,3}\.\d{1,3}\.\d{1,3}):(\d+)`)
	plainIPPortRegex  = regexp.MustCompile(`(?:^|[\s"'>])(\d{1,3}\.\d{1,3}\.\d{1,3}\.\d{1,3}):(\d+)`)
)

type Proxy struct {
	IP      string   `json:"ip"`
	Port    string   `json:"port"`
	Country string   `json:"country"`
	City    string   `json:"city"`
	Tags    []string `json:"tags"`
}

func (p Proxy) Addr() string {
	return p.IP + ":" + p.Port
}

func (p Proxy) String() string {
	return fmt.Sprintf("socks5://%s:%s", p.IP, p.Port)
}

// Scrape 支持以逗号分隔传入多个源（例如: url1,url2,url3）
func Scrape(urls string) ([]Proxy, error) {
	urlList := strings.Split(urls, ",")
	seen := make(map[string]bool)
	var allProxies []Proxy

	for _, rawURL := range urlList {
		targetURL := strings.TrimSpace(rawURL)
		if targetURL == "" {
			continue
		}

		proxies, err := scrapeSingle(targetURL)
		if err != nil {
			log.Printf("[scraper] 抓取源失败 [%s]: %v", targetURL, err)
			continue
		}

		for _, p := range proxies {
			addr := p.Addr()
			if !seen[addr] {
				seen[addr] = true
				allProxies = append(allProxies, p)
			}
		}
	}

	log.Printf("[scraper] 多源抓取汇总: 共获取到 %d 个去重代理 (来自 %d 个源)", len(allProxies), len(urlList))
	return allProxies, nil
}

func scrapeSingle(url string) ([]Proxy, error) {
	t := &http.Transport{}
	t.RegisterProtocol("file", http.NewFileTransport(http.Dir("/")))

	c := &http.Client{Transport: t}
	resp, err := c.Get(url)
	if err != nil {
		return nil, fmt.Errorf("fetch failed: %w", err)
	}
	defer resp.Body.Close()

	if resp.StatusCode != http.StatusOK {
		return nil, fmt.Errorf("unexpected status: %d", resp.StatusCode)
	}

	body, err := io.ReadAll(resp.Body)
	if err != nil {
		return nil, fmt.Errorf("read body failed: %w", err)
	}

	content := string(body)
	matches := socks5PrefixRegex.FindAllStringSubmatch(content, -1)

	// 如果没有带 socks5:// 前缀，尝试按纯 IP:Port 提取
	if len(matches) == 0 {
		matches = plainIPPortRegex.FindAllStringSubmatch(content, -1)
	}

	seen := make(map[string]bool)
	var proxies []Proxy

	for _, m := range matches {
		addr := m[1] + ":" + m[2]
		if seen[addr] {
			continue
		}
		seen[addr] = true
		proxies = append(proxies, Proxy{
			IP:   strings.TrimSpace(m[1]),
			Port: strings.TrimSpace(m[2]),
		})
	}

	log.Printf("[scraper] 源 [%s] 提取到 %d 个候选节点", url, len(proxies))
	return proxies, nil
}
