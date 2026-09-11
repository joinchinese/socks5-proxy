package main

import (
	"crypto/tls"
	"fmt"
	"log"
	"net"
	"net/http"
	"net/url"
	"strings"
	"sync"
	"time"
)

type ProxyPool struct {
	mu          sync.RWMutex
	proxies     []Proxy
	ruleManager *RuleManager
	currentIdx  map[string]int // 分类名 -> 当前激活节点下标
}

func NewProxyPool(rm *RuleManager) *ProxyPool {
	return &ProxyPool{
		ruleManager: rm,
		currentIdx:  make(map[string]int),
	}
}

// Add 实时追加单个测活成功的节点（并发安全、自动去重与标签合并）
func (p *ProxyPool) Add(px Proxy) {
	p.mu.Lock()
	defer p.mu.Unlock()

	for i, existing := range p.proxies {
		if existing.Addr() == px.Addr() {
			tagMap := make(map[string]bool)
			for _, t := range existing.Tags {
				tagMap[t] = true
			}
			for _, t := range px.Tags {
				tagMap[t] = true
			}
			var mergedTags []string
			for t := range tagMap {
				mergedTags = append(mergedTags, t)
			}
			p.proxies[i].Tags = mergedTags
			if px.Country != "" {
				p.proxies[i].Country = px.Country
			}
			if px.City != "" {
				p.proxies[i].City = px.City
			}
			return
		}
	}

	p.proxies = append(p.proxies, px)
	if len(p.proxies) == 1 {
		log.Printf("[pool] 首个可用节点就绪: %s (%s %s) Tags: %v", px.Addr(), px.Country, px.City, px.Tags)
	}
}

// Update 批量覆盖节点列表（全量测活完成时调用）
func (p *ProxyPool) Update(proxies []Proxy) {
	p.mu.Lock()
	defer p.mu.Unlock()
	p.proxies = proxies
	p.currentIdx = make(map[string]int)
	if len(proxies) > 0 {
		log.Printf("[pool] 代理池全量更新: %d 个可用节点", len(proxies))
	}
}

// getMatchedLocked 仅获取真正具备该分类标签的节点
func (p *ProxyPool) getMatchedLocked(category string) []Proxy {
	if category == "Default" || category == "" {
		return p.proxies
	}

	var matched []Proxy
	for _, px := range p.proxies {
		for _, tag := range px.Tags {
			if strings.EqualFold(tag, category) {
				matched = append(matched, px)
				break
			}
		}
	}
	return matched
}

// GetForCategory 获取指定分类当前激活的节点，若该专属分类暂无节点则降级到 Default
func (p *ProxyPool) GetForCategory(category string) (Proxy, bool) {
	p.mu.Lock()
	defer p.mu.Unlock()

	matched := p.getMatchedLocked(category)
	if len(matched) == 0 {
		matched = p.proxies
		if len(matched) == 0 {
			return Proxy{}, false
		}
	}

	idx := p.currentIdx[category]
	if idx >= len(matched) {
		idx = 0
		p.currentIdx[category] = 0
	}

	return matched[idx], true
}

// SwitchNextForCategory 轮换指定分类的下一个节点
func (p *ProxyPool) SwitchNextForCategory(category string) (Proxy, bool) {
	p.mu.Lock()
	defer p.mu.Unlock()

	matched := p.getMatchedLocked(category)
	if len(matched) == 0 {
		matched = p.proxies
		if len(matched) == 0 {
			return Proxy{}, false
		}
	}

	p.currentIdx[category] = (p.currentIdx[category] + 1) % len(matched)
	px := matched[p.currentIdx[category]]
	log.Printf("[pool] [%s] 切换至节点: %s (%s %s)", category, px.Addr(), px.Country, px.City)
	return px, true
}

// RemoveCurrentForCategory 移除指定分类当前失效的节点，并自动切换
func (p *ProxyPool) RemoveCurrentForCategory(category string) (Proxy, bool) {
	p.mu.Lock()
	defer p.mu.Unlock()

	matched := p.getMatchedLocked(category)
	if len(matched) == 0 {
		matched = p.proxies
		if len(matched) == 0 {
			return Proxy{}, false
		}
	}

	idx := p.currentIdx[category]
	if idx >= len(matched) {
		idx = 0
	}
	deadAddr := matched[idx].Addr()

	for i, px := range p.proxies {
		if px.Addr() == deadAddr {
			p.proxies = append(p.proxies[:i], p.proxies[i+1:]...)
			log.Printf("[pool] 节点失效已剔除: %s (关联分类: %s)", deadAddr, category)
			break
		}
	}

	newMatched := p.getMatchedLocked(category)
	if len(newMatched) == 0 {
		newMatched = p.proxies
		if len(newMatched) == 0 {
			p.currentIdx[category] = 0
			return Proxy{}, false
		}
	}

	if p.currentIdx[category] >= len(newMatched) {
		p.currentIdx[category] = 0
	}
	return newMatched[p.currentIdx[category]], true
}

// SwitchTo 手动将指定分类切换至特定 index
func (p *ProxyPool) SwitchTo(category string, index int) (Proxy, bool) {
	p.mu.Lock()
	defer p.mu.Unlock()

	matched := p.getMatchedLocked(category)
	if len(matched) == 0 {
		matched = p.proxies
	}
	if index < 0 || index >= len(matched) {
		return Proxy{}, false
	}

	p.currentIdx[category] = index
	px := matched[index]
	log.Printf("[pool] [%s] 手动指定节点: %s", category, px.Addr())
	return px, true
}

// GetActiveForCategory 仅获取真正具备该标签且当前激活的节点（用于 UI 状态展示，不乱降级）
func (p *ProxyPool) GetActiveForCategory(category string) (Proxy, bool) {
	p.mu.RLock()
	defer p.mu.RUnlock()

	var matched []Proxy
	if category == "Default" || category == "" {
		matched = p.proxies
	} else {
		for _, px := range p.proxies {
			for _, tag := range px.Tags {
				if strings.EqualFold(tag, category) {
					matched = append(matched, px)
					break
				}
			}
		}
	}

	if len(matched) == 0 {
		return Proxy{}, false
	}

	idx := p.currentIdx[category]
	if idx >= len(matched) {
		idx = 0
	}
	return matched[idx], true
}

// RealCountForCategory 获取指定分类真实具备该标签的节点数量
func (p *ProxyPool) RealCountForCategory(category string) int {
	p.mu.RLock()
	defer p.mu.RUnlock()

	if category == "Default" || category == "" {
		return len(p.proxies)
	}

	count := 0
	for _, px := range p.proxies {
		for _, tag := range px.Tags {
			if strings.EqualFold(tag, category) {
				count++
				break
			}
		}
	}
	return count
}

// TestAndAddRuleToAlive 动态添加规则时，后台对当前池内所有已存活节点快速测活并即时打标
func (p *ProxyPool) TestAndAddRuleToAlive(rule RouteRule, timeout time.Duration) {
	p.mu.RLock()
	proxies := make([]Proxy, len(p.proxies))
	copy(proxies, p.proxies)
	p.mu.RUnlock()

	if len(proxies) == 0 {
		return
	}

	log.Printf("[pool] 正在为当前 %d 个存活节点快速探测新规则 [%s]...", len(proxies), rule.Name)

	var wg sync.WaitGroup
	sem := make(chan struct{}, 15)

	for _, px := range proxies {
		wg.Add(1)
		sem <- struct{}{}
		go func(pItem Proxy) {
			defer wg.Done()
			defer func() { <-sem }()

			proxyURL, err := url.Parse(fmt.Sprintf("socks5://%s", pItem.Addr()))
			if err != nil {
				return
			}
			transport := &http.Transport{
				Proxy: http.ProxyURL(proxyURL),
				TLSClientConfig: &tls.Config{
					InsecureSkipVerify: false,
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

			if testSingleRule(client, rule, timeout) {
				p.AddTagToProxy(pItem.Addr(), rule.Name)
				log.Printf("[pool] 节点 %s 验证通过新规则 [%s]，已自动打标", pItem.Addr(), rule.Name)
			}
		}(px)
	}

	wg.Wait()
	log.Printf("[pool] 新规则 [%s] 探测就绪，匹配到可用节点数: %d", rule.Name, p.RealCountForCategory(rule.Name))
}

// AddTagToProxy 为指定地址的节点动态添加标签（去重）
func (p *ProxyPool) AddTagToProxy(addr string, tag string) {
	p.mu.Lock()
	defer p.mu.Unlock()

	for i, px := range p.proxies {
		if px.Addr() == addr {
			for _, t := range px.Tags {
				if strings.EqualFold(t, tag) {
					return
				}
			}
			p.proxies[i].Tags = append(p.proxies[i].Tags, tag)
			return
		}
	}
}

// RenameTag 重命名节点标签
func (p *ProxyPool) RenameTag(oldTag, newTag string) {
	p.mu.Lock()
	defer p.mu.Unlock()

	for i, px := range p.proxies {
		for j, t := range px.Tags {
			if strings.EqualFold(t, oldTag) {
				p.proxies[i].Tags[j] = newTag
			}
		}
	}
}

// RemoveTagFromAllProxies 当规则被删除时，从所有节点中清理该标签
func (p *ProxyPool) RemoveTagFromAllProxies(tag string) {
	p.mu.Lock()
	defer p.mu.Unlock()

	for i, px := range p.proxies {
		var newTags []string
		for _, t := range px.Tags {
			if !strings.EqualFold(t, tag) {
				newTags = append(newTags, t)
			}
		}
		p.proxies[i].Tags = newTags
	}
}

func (p *ProxyPool) Size() int {
	p.mu.RLock()
	defer p.mu.RUnlock()
	return len(p.proxies)
}

func (p *ProxyPool) All() []Proxy {
	p.mu.RLock()
	defer p.mu.RUnlock()
	res := make([]Proxy, len(p.proxies))
	copy(res, p.proxies)
	return res
}
