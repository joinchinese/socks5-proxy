package main

import (
	"context"
	"crypto/tls"
	"fmt"
	"io"
	"log"
	"net"
	"net/http"
	"net/url"
	"strings"
	"sync"
	"time"
)

var blockedCountries = map[string]bool{
	"china":     true,
	"hong kong": true,
}

// CheckProxies 并发检测代理节点并根据当前规则动态打标
func CheckProxies(proxies []Proxy, timeout time.Duration, maxConcurrent int, pool *ProxyPool) []Proxy {
	var (
		mu    sync.Mutex
		alive []Proxy
		wg    sync.WaitGroup
		sem   = make(chan struct{}, maxConcurrent)
	)

	// 获取当前所有规则用于打标探测
	var currentRules []RouteRule
	if pool != nil && pool.ruleManager != nil {
		currentRules = pool.ruleManager.All()
	}

	for _, p := range proxies {
		wg.Add(1)
		sem <- struct{}{}
		go func(px Proxy) {
			defer wg.Done()
			defer func() { <-sem }()

			// 1. 地理位置初筛
			country, city := LookupGeo(px.IP, timeout)
			px.Country = strings.TrimSpace(country)
			px.City = strings.TrimSpace(city)

			if blockedCountries[strings.ToLower(px.Country)] {
				return
			}

			// 2. 基础出口极速初筛
			if !checkGoogle(px, timeout) {
				return
			}

			// 3. 针对所有规则动态测活打标
			passedTags := checkRules(px, currentRules, timeout)
			if len(passedTags) == 0 {
				return // 无任何一项规则通过，判定为死节点
			}

			px.Tags = passedTags
			log.Printf("[checker] %s OK (%s %s) [支持规则: %s]", px.Addr(), px.Country, px.City, strings.Join(passedTags, ", "))

			// 4. 实时推入全局代理池，秒级生效
			if pool != nil {
				pool.Add(px)
			}

			mu.Lock()
			alive = append(alive, px)
			mu.Unlock()
		}(p)
	}

	wg.Wait()
	log.Printf("[checker] %d/%d 个节点验证合格入池", len(alive), len(proxies))
	return alive
}

// checkRules 根据当前规则列表，并发检测该节点支持哪些规则
func checkRules(p Proxy, rules []RouteRule, timeout time.Duration) []string {
	proxyURL, err := url.Parse(fmt.Sprintf("socks5://%s", p.Addr()))
	if err != nil {
		return nil
	}

	transport := &http.Transport{
		Proxy: http.ProxyURL(proxyURL),
		TLSClientConfig: &tls.Config{
			InsecureSkipVerify: false, // 严格校验证书
		},
		DialContext: (&net.Dialer{
			Timeout: timeout,
		}).DialContext,
		ResponseHeaderTimeout: timeout,
		DisableKeepAlives:     true,
	}

	client := &http.Client{
		Transport: transport,
		Timeout:   timeout,
	}

	var (
		mu         sync.Mutex
		passedTags []string
		wg         sync.WaitGroup
	)

	for _, rule := range rules {
		wg.Add(1)
		go func(r RouteRule) {
			defer wg.Done()

			if testSingleRule(client, r, timeout) {
				mu.Lock()
				passedTags = append(passedTags, r.Name)
				mu.Unlock()
			}
		}(rule)
	}

	wg.Wait()
	return passedTags
}

// testSingleRule 测试节点是否满足某一条规则
func testSingleRule(client *http.Client, rule RouteRule, timeout time.Duration) bool {
	lowerName := strings.ToLower(rule.Name)

	var testURL string
	var validate func(code int) bool

	switch lowerName {
	case "openai":
		testURL = "https://api.openai.com/v1/models"
		validate = func(code int) bool { return code == http.StatusUnauthorized || code == http.StatusOK }
	case "anthropic", "claude":
		testURL = "https://api.anthropic.com/v1/models"
		validate = func(code int) bool { return code == http.StatusUnauthorized || code == http.StatusOK }
	case "gemini":
		testURL = "https://generativelanguage.googleapis.com/$discovery/rest?version=v1beta"
		validate = func(code int) bool { return code == http.StatusOK }
	case "grok":
		testURL = "https://api.x.ai/v1/models"
		validate = func(code int) bool { return code == http.StatusUnauthorized || code == http.StatusOK }
	default:
		// 用户自定义规则：取第一个域名进行 HTTPS 连通性测试
		if len(rule.Domains) == 0 {
			return false
		}
		targetDomain := strings.TrimSpace(rule.Domains[0])
		if !strings.HasPrefix(targetDomain, "http://") && !strings.HasPrefix(targetDomain, "https://") {
			testURL = "https://" + targetDomain
		} else {
			testURL = targetDomain
		}
		validate = func(code int) bool { return code > 0 && code < 500 } // 只要有有效 HTTP/HTTPS 响应即通过
	}

	ctx, cancel := context.WithTimeout(context.Background(), timeout)
	defer cancel()

	req, err := http.NewRequestWithContext(ctx, "GET", testURL, nil)
	if err != nil {
		return false
	}
	req.Header.Set("User-Agent", "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36")

	resp, err := client.Do(req)
	if err != nil {
		return false
	}
	defer resp.Body.Close()
	io.Copy(io.Discard, resp.Body)

	return validate(resp.StatusCode)
}

func checkGoogle(p Proxy, timeout time.Duration) bool {
	conn, err := net.DialTimeout("tcp", p.Addr(), timeout)
	if err != nil {
		return false
	}
	defer conn.Close()
	conn.SetDeadline(time.Now().Add(timeout))

	if _, err := conn.Write([]byte{0x05, 0x01, 0x00}); err != nil {
		return false
	}
	buf := make([]byte, 2)
	if _, err := io.ReadFull(conn, buf); err != nil || buf[0] != 0x05 {
		return false
	}

	target := "www.google.com"
	req := []byte{0x05, 0x01, 0x00, 0x03, byte(len(target))}
	req = append(req, []byte(target)...)
	req = append(req, 0x00, 0x50)

	if _, err := conn.Write(req); err != nil {
		return false
	}

	resp := make([]byte, 256)
	n, err := conn.Read(resp)
	if err != nil || n < 2 || resp[1] != 0x00 {
		return false
	}

	httpReq := "GET /generate_204 HTTP/1.1\r\nHost: www.google.com\r\nConnection: close\r\n\r\n"
	if _, err := conn.Write([]byte(httpReq)); err != nil {
		return false
	}

	respBuf := make([]byte, 512)
	n, err = conn.Read(respBuf)
	if err != nil || n < 12 {
		return false
	}

	return string(respBuf[:4]) == "HTTP"
}

func LookupGeo(ip string, timeout time.Duration) (country, city string) {
	conn, err := net.DialTimeout("tcp", "ip-api.com:80", timeout)
	if err != nil {
		return "Unknown", ""
	}
	defer conn.Close()
	conn.SetDeadline(time.Now().Add(timeout))

	req := fmt.Sprintf("GET /csv/%s?fields=country,city HTTP/1.1\r\nHost: ip-api.com\r\nConnection: close\r\n\r\n", ip)
	conn.Write([]byte(req))

	buf := make([]byte, 1024)
	n, err := conn.Read(buf)
	if err != nil || n == 0 {
		return "Unknown", ""
	}

	body := string(buf[:n])
	for i := 0; i < len(body)-3; i++ {
		if body[i:i+4] == "\r\n\r\n" {
			body = body[i+4:]
			break
		}
	}

	for i, c := range body {
		if c == ',' {
			return body[:i], body[i+1:]
		}
	}
	return body, ""
}
