package main

import (
	"log"
	"math/rand"
	"sync"
	"time"
)

var (
	lastScrapeTime time.Time
	nextScrapeTime time.Time
	scrapeMu       sync.RWMutex
	refreshChan    = make(chan struct{}, 1) // manual refresh trigger
)

func getScrapeTimes() (last, next time.Time) {
	scrapeMu.RLock()
	defer scrapeMu.RUnlock()
	return lastScrapeTime, nextScrapeTime
}

func main() {
	cfg := ParseConfig()

	log.Printf("socks5-pool starting...")
	log.Printf("  listen:   %s", cfg.ListenAddr)
	log.Printf("  status:   %s", cfg.StatusAddr)
	log.Printf("  source:   %s", cfg.ScrapeURL)
	log.Printf("  scrape:   every %s", cfg.ScrapeInterval)

	pool := NewProxyPool()

	// 1. 【优先启动 Web 状态面板】
	// 无论抓取多少个节点，确保 8080 端口在第 0.1 秒立即进入监听状态，彻底解决 Cloudflare 502
	go func() {
		status := NewStatusServer(pool)
		log.Printf("[status] dashboard at http://%s", cfg.StatusAddr)
		if err := status.Start(cfg.StatusAddr); err != nil {
			log.Printf("[status] failed to start: %v", err)
		}
	}()

	// 2. 【后台进行初次抓取与定期测活】
	// 避免初次测活 2000 多个节点时同步卡死主线程
	go func() {
		log.Printf("[main] 正在后台启动初始代理抓取与测活...")
		refreshPool(cfg, pool)

		if pool.Size() == 0 {
			log.Printf("[warn] no alive proxies found, will retry on next scrape cycle")
		}

		ticker := time.NewTicker(cfg.ScrapeInterval)
		defer ticker.Stop()
		for {
			select {
			case <-ticker.C:
				refreshPool(cfg, pool)
			case <-refreshChan:
				log.Printf("[main] manual refresh triggered")
				refreshPool(cfg, pool)
				ticker.Reset(cfg.ScrapeInterval)
			}
		}
	}()

	// 3. 【后台代理轮换逻辑】
	// 每 3-6 分钟自动随机切换当前使用的活动节点
	go func() {
		for {
			delay := 3*time.Minute + time.Duration(rand.Intn(4))*time.Minute
			time.Sleep(delay)
			if pool.Size() == 0 {
				log.Printf("[main] pool empty, triggering immediate refresh")
				TriggerRefresh()
			} else if pool.Size() > 1 {
				pool.SwitchNext()
			}
		}
	}()

	// 4. 【启动 SOCKS5 代理服务（阻塞主进程）】
	server := NewServer(cfg.ListenAddr, pool, cfg.AuthUser, cfg.AuthPass)
	log.Fatal(server.Start())
}

func refreshPool(cfg *Config, pool *ProxyPool) {
	proxies, err := Scrape(cfg.ScrapeURL)
	if err != nil {
		log.Printf("[error] scrape failed: %v", err)
		return
	}

	alive := CheckProxies(proxies, cfg.CheckTimeout, cfg.MaxConcurrent)
	pool.Update(alive)

	scrapeMu.Lock()
	lastScrapeTime = time.Now()
	nextScrapeTime = lastScrapeTime.Add(cfg.ScrapeInterval)
	scrapeMu.Unlock()

	log.Printf("[main] pool refreshed: %d alive proxies", pool.Size())
}

// TriggerRefresh 发送手动刷新信号 (非阻塞)
func TriggerRefresh() {
	select {
	case refreshChan <- struct{}{}:
	default:
		// 已经存在刷新请求在排队，直接忽略
	}
}
