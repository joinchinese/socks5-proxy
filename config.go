package main

import (
	"flag"
	"os"
	"time"
)

type Config struct {
	ListenAddr     string
	StatusAddr     string
	ScrapeURL      string
	ScrapeInterval time.Duration
	CheckTimeout   time.Duration
	MaxConcurrent  int
	AuthUser       string // 认证用户名
	AuthPass       string // 认证密码
	AdminPass      string // Web UI 管理密码
}

func ParseConfig() *Config {
	cfg := &Config{}
	flag.StringVar(&cfg.ListenAddr, "listen", "0.0.0.0:1080", "local SOCKS5 listen address")
	flag.StringVar(&cfg.StatusAddr, "status", "127.0.0.1:8080", "HTTP status dashboard address")
	flag.StringVar(&cfg.ScrapeURL, "url", "https://socks5-proxy.github.io/", "proxy list URL")
	flag.DurationVar(&cfg.ScrapeInterval, "scrape-interval", 45*time.Minute, "scrape interval")
	flag.DurationVar(&cfg.CheckTimeout, "check-timeout", 8*time.Second, "proxy check timeout")
	flag.IntVar(&cfg.MaxConcurrent, "max-concurrent", 5, "max concurrent health checks")
	flag.StringVar(&cfg.AuthUser, "user", "admin123", "SOCKS5 authentication username")
	flag.StringVar(&cfg.AuthPass, "pass", "admin123", "SOCKS5 authentication password")
	flag.StringVar(&cfg.AdminPass, "admin-pass", "", "Web UI admin password (defaults to -pass)")
	flag.Parse()

	// 自动读取环境变量（优先使用环境变量中的账密与端口）
	if u := os.Getenv("AUTH_USER"); u != "" {
		cfg.AuthUser = u
	}
	if p := os.Getenv("AUTH_PASS"); p != "" {
		cfg.AuthPass = p
	}
	if ap := os.Getenv("ADMIN_PASS"); ap != "" {
		cfg.AdminPass = ap
	}
	if cfg.AdminPass == "" {
		cfg.AdminPass = cfg.AuthPass
	}

	// 自动适配容器分配的公网端口
	port := os.Getenv("SERVER_PORT")
	if port == "" {
		port = os.Getenv("PORT")
	}
	if port != "" {
		cfg.ListenAddr = "0.0.0.0:" + port
	}

	return cfg
}
