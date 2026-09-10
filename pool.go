package main

import (
	"log"
	"sync"
)

// ProxyPool holds a list of verified proxies.
// It picks one "current" proxy and sticks with it until failure.
type ProxyPool struct {
	mu      sync.RWMutex
	proxies []Proxy
	current int // index of the current active proxy
}

func NewProxyPool() *ProxyPool {
	return &ProxyPool{}
}

// Add 实时追加单个测活成功的节点（并发安全、自动去重）
// 测出一个立即生效，无需等整批节点跑完
func (p *ProxyPool) Add(px Proxy) {
	p.mu.Lock()
	defer p.mu.Unlock()

	// 避免重复添加
	for _, existing := range p.proxies {
		if existing.Addr() == px.Addr() {
			return
		}
	}

	p.proxies = append(p.proxies, px)
	// 如果之前池子是空的，立即将当前活动节点指向第一个节点
	if len(p.proxies) == 1 {
		p.current = 0
		log.Printf("[pool] 首个可用节点就绪: %s (%s %s)", px.Addr(), px.Country, px.City)
	}
}

// Update replaces the proxy list with new verified proxies.
// Resets current to 0 (pick the first one).
func (p *ProxyPool) Update(proxies []Proxy) {
	p.mu.Lock()
	defer p.mu.Unlock()
	p.proxies = proxies
	p.current = 0
	if len(proxies) > 0 {
		log.Printf("[pool] active proxy: %s (%s %s)", proxies[0].Addr(), proxies[0].Country, proxies[0].City)
	}
}

// Current returns the current active proxy.
func (p *ProxyPool) Current() (Proxy, bool) {
	p.mu.RLock()
	defer p.mu.RUnlock()
	if len(p.proxies) == 0 {
		return Proxy{}, false
	}
	return p.proxies[p.current], true
}

// SwitchNext moves to the next proxy in the list. Returns the new proxy.
func (p *ProxyPool) SwitchNext() (Proxy, bool) {
	p.mu.Lock()
	defer p.mu.Unlock()
	if len(p.proxies) == 0 {
		return Proxy{}, false
	}
	p.current = (p.current + 1) % len(p.proxies)
	px := p.proxies[p.current]
	log.Printf("[pool] switched to: %s (%s %s)", px.Addr(), px.Country, px.City)
	return px, true
}

// SwitchTo switches to a specific proxy by index. Returns the proxy.
func (p *ProxyPool) SwitchTo(index int) (Proxy, bool) {
	p.mu.Lock()
	defer p.mu.Unlock()
	if index < 0 || index >= len(p.proxies) {
		return Proxy{}, false
	}
	p.current = index
	px := p.proxies[p.current]
	log.Printf("[pool] switched to: %s (%s %s)", px.Addr(), px.Country, px.City)
	return px, true
}

// CurrentIndex returns the current active index.
func (p *ProxyPool) CurrentIndex() int {
	p.mu.RLock()
	defer p.mu.RUnlock()
	return p.current
}

// Size returns the current number of proxies in the pool.
func (p *ProxyPool) Size() int {
	p.mu.RLock()
	defer p.mu.RUnlock()
	return len(p.proxies)
}

// All returns a copy of all proxies in the pool.
func (p *ProxyPool) All() []Proxy {
	p.mu.RLock()
	defer p.mu.RUnlock()
	result := make([]Proxy, len(p.proxies))
	copy(result, p.proxies)
	return result
}
