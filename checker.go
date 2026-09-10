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

// Blocked countries: China mainland + Hong Kong (can't access Google/AI)
var blockedCountries = map[string]bool{
	"china":     true,
	"hong kong": true,
}

// AI 目标检查定义
type AITarget struct {
	Name     string
	URL      string
	Validate func(statusCode int) bool
}

var aiTargets = []AITarget{
	{
		Name: "OpenAI",
		URL:  "https://api.openai.com/v1/models",
		// 未授权会返回 401 说明成功到达网关且未被 Cloudflare WAF 盾拦截
		Validate: func(code int) bool { return code == http.StatusUnauthorized || code == http.StatusOK },
	},
	{
		Name: "Anthropic",
		URL:  "https://api.anthropic.com/v1/models",
		Validate: func(code int) bool { return code == http.StatusUnauthorized || code == http.StatusOK },
	},
	{
		Name: "Gemini",
		URL:  "https://generativelanguage.googleapis.com/$discovery/rest?version=v1beta",
		// 公开 Discovery 接口，正常直接返回 200 OK
		Validate: func(code int) bool { return code == http.StatusOK },
	},
	{
		Name: "Grok",
		URL:  "https://api.x.ai/v1/models",
		Validate: func(code int) bool { return code == http.StatusUnauthorized || code == http.StatusOK },
	},
}

// CheckProxies concurrently checks a list of proxies.
func CheckProxies(proxies []Proxy, timeout time.Duration, maxConcurrent int, pool *ProxyPool) []Proxy {
	var (
		mu    sync.Mutex
		alive []Proxy
		wg    sync.WaitGroup
		sem   = make(chan struct{}, maxConcurrent)
	)

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
				log.Printf("[checker] %s skipped (%s)", px.Addr(), px.Country)
				return
			}

			// 2. 基础出口连通性（极速过滤死节点，不浪费时间）
			if !checkGoogle(px, timeout) {
				return
			}

			// 3. AI 核心质量检测（必须通过 OpenAI、Anthropic、Gemini、Grok 中至少 2 项）
			passedAIs := checkAIQuality(px, timeout)
			if len(passedAIs) < 2 {
				log.Printf("[checker] %s skipped (基础通但 AI 质量不足: 仅通过 %v)", px.Addr(), passedAIs)
				return
			}

			// 通过检测，打印成功日志
			log.Printf("[checker] %s OK (%s %s) [AI通过: %s]", px.Addr(), px.Country, px.City, strings.Join(passedAIs, ", "))

			// 实时上屏入池
			if pool != nil {
				pool.Add(px)
			}

			mu.Lock()
			alive = append(alive, px)
			mu.Unlock()
		}(p)
	}

	wg.Wait()
	log.Printf("[checker] %d/%d proxies alive (Google-verified, non-CN/HK, AI >= 2)", len(alive), len(proxies))
	return alive
}

// checkAIQuality 并发检测 4 大模型端点，返回测试通过的 AI 名称列表
func checkAIQuality(p Proxy, timeout time.Duration) []string {
	proxyURL, err := url.Parse(fmt.Sprintf("socks5://%s", p.Addr()))
	if err != nil {
		return nil
	}

	// 使用标准库的 SOCKS5 HTTP Client，强制严格校验证书（防中间人过期假证书/劫持）
	transport := &http.Transport{
		Proxy: http.ProxyURL(proxyURL),
		TLSClientConfig: &tls.Config{
			InsecureSkipVerify: false, // 严格验证证书合法性与有效期
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
		mu     sync.Mutex
		passed []string
		wg     sync.WaitGroup
	)

	for _, target := range aiTargets {
		wg.Add(1)
		go func(t AITarget) {
			defer wg.Done()

			ctx, cancel := context.WithTimeout(context.Background(), timeout)
			defer cancel()

			req, err := http.NewRequestWithContext(ctx, "GET", t.URL, nil)
			if err != nil {
				return
			}
			// 设置现代浏览器 User-Agent，避免被云厂商 Cloudflare 盾直接拒绝
			req.Header.Set("User-Agent", "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/128.0.0.0 Safari/537.36")
			req.Header.Set("Accept", "*/*")

			resp, err := client.Do(req)
			if err != nil {
				return // 握手失败、证书过期、connection reset 均直接返回
			}
			defer resp.Body.Close()
			io.Copy(io.Discard, resp.Body)

			if t.Validate(resp.StatusCode) {
				mu.Lock()
				passed = append(passed, t.Name)
				mu.Unlock()
			}
		}(target)
	}

	wg.Wait()
	return passed
}

// checkGoogle 连接 Google 204 端点进行极速基础测活
func checkGoogle(p Proxy, timeout time.Duration) bool {
	conn, err := net.DialTimeout("tcp", p.Addr(), timeout)
	if err != nil {
		return false
	}
	defer conn.Close()
	conn.SetDeadline(time.Now().Add(timeout))

	// SOCKS5 greeting
	if _, err := conn.Write([]byte{0x05, 0x01, 0x00}); err != nil {
		return false
	}
	buf := make([]byte, 2)
	if _, err := io.ReadFull(conn, buf); err != nil || buf[0] != 0x05 {
		return false
	}

	// Connect to www.google.com:80 through proxy
	target := "www.google.com"
	req := []byte{0x05, 0x01, 0x00, 0x03, byte(len(target))}
	req = append(req, []byte(target)...)
	req = append(req, 0x00, 0x50) // port 80

	if _, err := conn.Write(req); err != nil {
		return false
	}

	resp := make([]byte, 256)
	n, err := conn.Read(resp)
	if err != nil || n < 2 || resp[1] != 0x00 {
		return false
	}

	// Send HTTP request to Google's generate_204 endpoint
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

// LookupGeo 查询 ip-api.com 获取国家归属地
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
