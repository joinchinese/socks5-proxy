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

	// 初始化分流规则管理器（持久化到当前目录 rules.json）
	rm := NewRuleManager("rules.json")
	pool := NewProxyPool(rm)

	// 1. 【优先秒起 Web 状态面板】确保 8080 端口第 0.1 秒立即进入监听，彻底告别 502
	go func() {
		status := NewStatusServer(pool, cfg.AdminPass, cfg.ListenAddr)
		log.Printf("[status] dashboard at http://%s", cfg.StatusAddr)
		if err := status.Start(cfg.StatusAddr); err != nil {
			log.Printf("[status] failed to start: %v", err)
		}
	}()

	// 2. 【后台进行初次抓取与测活】
	go func() {
		log.Printf("[main] 正在后台启动初始代理抓取与测活...")
		refreshPool(cfg, pool)

		if pool.Size() == 0 {
			log.Printf("[warn] 初始未发现可用节点，将在下一个抓取周期重试")
		}

		ticker := time.NewTicker(cfg.ScrapeInterval)
		defer ticker.Stop()
		for {
			select {
			case <-ticker.C:
				refreshPool(cfg, pool)
			case <-refreshChan:
				log.Printf("[main] 手动刷新触发...")
				refreshPool(cfg, pool)
				ticker.Reset(cfg.ScrapeInterval)
			}
		}
	}()

	// 3. 【后台自动随机轮换代理节点 (每 3~6 分钟)】
	go func() {
		for {
			delay := 3*time.Minute + time.Duration(rand.Intn(4))*time.Minute
			time.Sleep(delay)
			if pool.Size() == 0 {
				log.Printf("[main] 代理池为空，触发紧急刷新")
				TriggerRefresh()
			} else {
				// 对每个规则分类顺延切换下一个可用节点
				if pool.ruleManager != nil {
					for _, r := range pool.ruleManager.All() {
						pool.SwitchNextForCategory(r.Name)
					}
				}
				pool.SwitchNextForCategory("Default")
			}
		}
	}()

	// 4. 【启动 SOCKS5 单端口智能分流服务（阻塞主进程）】
	server := NewServer(cfg.ListenAddr, pool, cfg.AuthUser, cfg.AuthPass)
	log.Fatal(server.Start())
}

func refreshPool(cfg *Config, pool *ProxyPool) {
	proxies, err := Scrape(cfg.ScrapeURL)
	if err != nil {
		log.Printf("[error] 抓取代理源失败: %v", err)
		return
	}

	alive := CheckProxies(proxies, cfg.CheckTimeout, cfg.MaxConcurrent, pool)
	pool.Update(alive)

	scrapeMu.Lock()
	lastScrapeTime = time.Now()
	nextScrapeTime = lastScrapeTime.Add(cfg.ScrapeInterval)
	scrapeMu.Unlock()

	log.Printf("[main] 代理池刷新就绪: 共 %d 个合格代理", pool.Size())
}

// TriggerRefresh 发送手动刷新信号 (非阻塞)
func TriggerRefresh() {
	select {
	case refreshChan <- struct{}{}:
	default:
	}
}
