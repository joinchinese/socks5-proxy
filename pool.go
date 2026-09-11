package main

import (
	"log"
	"strings"
	"sync"
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
			// 更新已有节点的标签与城市
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

// Update 批量覆盖节点列表（通常用于定时刷新完成）
func (p *ProxyPool) Update(proxies []Proxy) {
	p.mu.Lock()
	defer p.mu.Unlock()
	p.proxies = proxies
	p.currentIdx = make(map[string]int)
	if len(proxies) > 0 {
		log.Printf("[pool] 代理池全量更新: %d 个可用节点", len(proxies))
	}
}

// filterByCategory 根据分类标签筛选可用节点
func (p *ProxyPool) filterByCategoryLocked(category string) []Proxy {
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

	// 若专属分类暂无节点，降级返回全部节点
	if len(matched) == 0 {
		return p.proxies
	}
	return matched
}

// GetForCategory 获取指定分类当前激活的节点
func (p *ProxyPool) GetForCategory(category string) (Proxy, bool) {
	p.mu.Lock()
	defer p.mu.Unlock()

	list := p.filterByCategoryLocked(category)
	if len(list) == 0 {
		return Proxy{}, false
	}

	idx := p.currentIdx[category]
	if idx >= len(list) {
		idx = 0
		p.currentIdx[category] = 0
	}

	return list[idx], true
}

// SwitchNextForCategory 轮换指定分类的下一个节点
func (p *ProxyPool) SwitchNextForCategory(category string) (Proxy, bool) {
	p.mu.Lock()
	defer p.mu.Unlock()

	list := p.filterByCategoryLocked(category)
	if len(list) == 0 {
		return Proxy{}, false
	}

	p.currentIdx[category] = (p.currentIdx[category] + 1) % len(list)
	px := list[p.currentIdx[category]]
	log.Printf("[pool] [%s] 切换至节点: %s (%s %s)", category, px.Addr(), px.Country, px.City)
	return px, true
}

// RemoveCurrentForCategory 移除指定分类当前失效的节点，并自动切换
func (p *ProxyPool) RemoveCurrentForCategory(category string) (Proxy, bool) {
	p.mu.Lock()
	defer p.mu.Unlock()

	list := p.filterByCategoryLocked(category)
	if len(list) == 0 {
		return Proxy{}, false
	}

	idx := p.currentIdx[category]
	if idx >= len(list) {
		idx = 0
	}
	deadAddr := list[idx].Addr()

	// 从全局代理池中物理删除该失效节点
	for i, px := range p.proxies {
		if px.Addr() == deadAddr {
			p.proxies = append(p.proxies[:i], p.proxies[i+1:]...)
			log.Printf("[pool] 节点失效已剔除: %s (关联分类: %s)", deadAddr, category)
			break
		}
	}

	// 重新获取列表
	newList := p.filterByCategoryLocked(category)
	if len(newList) == 0 {
		p.currentIdx[category] = 0
		return Proxy{}, false
	}

	if p.currentIdx[category] >= len(newList) {
		p.currentIdx[category] = 0
	}
	return newList[p.currentIdx[category]], true
}

// SwitchTo 手动将指定分类切换至特定 index
func (p *ProxyPool) SwitchTo(category string, index int) (Proxy, bool) {
	p.mu.Lock()
	defer p.mu.Unlock()

	list := p.filterByCategoryLocked(category)
	if index < 0 || index >= len(list) {
		return Proxy{}, false
	}

	p.currentIdx[category] = index
	px := list[index]
	log.Printf("[pool] [%s] 手动指定节点: %s", category, px.Addr())
	return px, true
}

// GetActiveForCategory 获取当前分类正在服务的节点
func (p *ProxyPool) GetActiveForCategory(category string) (Proxy, bool) {
	p.mu.RLock()
	defer p.mu.RUnlock()

	list := p.filterByCategoryLocked(category)
	if len(list) == 0 {
		return Proxy{}, false
	}
	idx := p.currentIdx[category]
	if idx >= len(list) {
		idx = 0
	}
	return list[idx], true
}

// CountForCategory 获取指定分类的节点数量
func (p *ProxyPool) CountForCategory(category string) int {
	p.mu.RLock()
	defer p.mu.RUnlock()
	return len(p.filterByCategoryLocked(category))
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
