package main

import (
	"encoding/json"
	"fmt"
	"html/template"
	"io"
	"log"
	"net"
	"net/http"
	"strconv"
	"strings"
	"sync"
	"time"
)

type StatusServer struct {
	pool      *ProxyPool
	adminPass string
	listenCfg string
	publicIP  string
	ipMu      sync.RWMutex
}

type StatusData struct {
	Total           int                  `json:"total"`
	PublicEndpoint  string               `json:"public_endpoint"`
	LastScrape      string               `json:"last_scrape"`
	NextScrape      string               `json:"next_scrape"`
	ActiveOutbounds []RuleOutboundStatus `json:"active_outbounds"`
	Proxies         []ProxyStatus        `json:"proxies"`
}

type RuleOutboundStatus struct {
	ID       string `json:"id"`
	Name     string `json:"name"`
	Domains  string `json:"domains"`
	ActiveIP string `json:"active_ip"`
	Location string `json:"location"`
	Count    int    `json:"count"`
}

type ProxyStatus struct {
	Addr    string   `json:"addr"`
	Country string   `json:"country"`
	City    string   `json:"city"`
	Tags    []string `json:"tags"`
	Active  string   `json:"active"` // 当前为哪个规则激活
}

func NewStatusServer(pool *ProxyPool, adminPass, listenCfg string) *StatusServer {
	s := &StatusServer{
		pool:      pool,
		adminPass: adminPass,
		listenCfg: listenCfg,
		publicIP:  "127.0.0.1",
	}

	go s.detectPublicIP()
	return s
}

func (s *StatusServer) detectPublicIP() {
	endpoints := []string{
		"https://api.ipify.org",
		"https://icanhazip.com",
		"https://ifconfig.me/ip",
	}

	client := &http.Client{Timeout: 5 * time.Second}
	for _, ep := range endpoints {
		resp, err := client.Get(ep)
		if err == nil && resp.StatusCode == http.StatusOK {
			body, _ := io.ReadAll(resp.Body)
			resp.Body.Close()
			ip := strings.TrimSpace(string(body))
			if net.ParseIP(ip) != nil {
				s.ipMu.Lock()
				s.publicIP = ip
				s.ipMu.Unlock()
				log.Printf("[status] 自动获取到服务器公网 IP: %s", ip)
				return
			}
		}
	}
}

func (s *StatusServer) getPublicEndpoint() string {
	s.ipMu.RLock()
	ip := s.publicIP
	s.ipMu.RUnlock()

	_, port, err := net.SplitHostPort(s.listenCfg)
	if err != nil {
		port = "1080"
	}
	return fmt.Sprintf("%s:%s", ip, port)
}

func (s *StatusServer) checkAuth(r *http.Request) bool {
	if s.adminPass == "" {
		return true
	}

	authHeader := r.Header.Get("Authorization")
	if strings.HasPrefix(authHeader, "Bearer ") {
		token := strings.TrimPrefix(authHeader, "Bearer ")
		if token == s.adminPass {
			return true
		}
	}

	if cookie, err := r.Cookie("admin_token"); err == nil && cookie.Value == s.adminPass {
		return true
	}

	if r.URL.Query().Get("token") == s.adminPass {
		return true
	}

	return false
}

func (s *StatusServer) Start(addr string) error {
	mux := http.NewServeMux()
	mux.HandleFunc("/", s.handleDashboard)
	mux.HandleFunc("/api/auth", s.handleAuth)
	mux.HandleFunc("/api/status", s.handleAPI)
	mux.HandleFunc("/api/refresh", s.handleRefresh)
	mux.HandleFunc("/api/switch", s.handleSwitch)
	mux.HandleFunc("/api/rules/add", s.handleAddRule)
	mux.HandleFunc("/api/rules/delete", s.handleDeleteRule)
	return http.ListenAndServe(addr, mux)
}

func (s *StatusServer) handleAuth(w http.ResponseWriter, r *http.Request) {
	w.Header().Set("Content-Type", "application/json")
	if r.Method != http.MethodPost {
		w.WriteHeader(http.StatusMethodNotAllowed)
		return
	}

	var req struct {
		Password string `json:"password"`
	}
	if err := json.NewDecoder(r.Body).Decode(&req); err != nil {
		w.WriteHeader(http.StatusBadRequest)
		return
	}

	if s.adminPass != "" && req.Password != s.adminPass {
		w.WriteHeader(http.StatusUnauthorized)
		w.Write([]byte(`{"error":"invalid password"}`))
		return
	}

	w.Write([]byte(`{"status":"ok"}`))
}

func (s *StatusServer) getStatusData() StatusData {
	proxies := s.pool.All()
	last, next := getScrapeTimes()

	beijingLoc := time.FixedZone("CST", 8*3600)
	var lastStr, nextStr string
	if !last.IsZero() {
		lastStr = last.In(beijingLoc).Format("2006-01-02 15:04:05")
	}
	if !next.IsZero() {
		nextStr = next.In(beijingLoc).Format("2006-01-02 15:04:05")
	}

	var outbounds []RuleOutboundStatus
	activeMap := make(map[string]string)

	if s.pool.ruleManager != nil {
		for _, r := range s.pool.ruleManager.All() {
			cnt := s.pool.RealCountForCategory(r.Name)
			activePx, ok := s.pool.GetActiveForCategory(r.Name)

			var activeIP, location string
			if ok {
				activeIP = activePx.Addr()
				location = fmt.Sprintf("%s · %s", activePx.Country, activePx.City)
				if existing, exists := activeMap[activePx.Addr()]; exists {
					activeMap[activePx.Addr()] = existing + ", " + r.Name
				} else {
					activeMap[activePx.Addr()] = r.Name
				}
			} else {
				activeIP = "等待测活匹配..."
				location = strings.Join(r.Domains, ",")
			}

			outbounds = append(outbounds, RuleOutboundStatus{
				ID:       r.ID,
				Name:     r.Name,
				Domains:  strings.Join(r.Domains, ", "),
				ActiveIP: activeIP,
				Location: location,
				Count:    cnt,
			})
		}
	}

	var ps []ProxyStatus
	for _, p := range proxies {
		act := activeMap[p.Addr()]
		ps = append(ps, ProxyStatus{
			Addr:    p.Addr(),
			Country: p.Country,
			City:    p.City,
			Tags:    p.Tags,
			Active:  act,
		})
	}

	return StatusData{
		Total:           len(proxies),
		PublicEndpoint:  s.getPublicEndpoint(),
		LastScrape:      lastStr,
		NextScrape:      nextStr,
		ActiveOutbounds: outbounds,
		Proxies:         ps,
	}
}

func (s *StatusServer) handleAPI(w http.ResponseWriter, r *http.Request) {
	w.Header().Set("Content-Type", "application/json")
	if !s.checkAuth(r) {
		w.WriteHeader(http.StatusUnauthorized)
		w.Write([]byte(`{"error":"unauthorized"}`))
		return
	}
	json.NewEncoder(w).Encode(s.getStatusData())
}

func (s *StatusServer) handleAddRule(w http.ResponseWriter, r *http.Request) {
	w.Header().Set("Content-Type", "application/json")
	if !s.checkAuth(r) {
		w.WriteHeader(http.StatusUnauthorized)
		return
	}

	var req struct {
		Name    string `json:"name"`
		Domains string `json:"domains"`
	}
	if err := json.NewDecoder(r.Body).Decode(&req); err != nil || req.Name == "" || req.Domains == "" {
		w.WriteHeader(http.StatusBadRequest)
		w.Write([]byte(`{"error":"invalid parameters"}`))
		return
	}

	parts := strings.Split(req.Domains, ",")
	var cleanDomains []string
	for _, d := range parts {
		trimmed := strings.TrimSpace(d)
		if trimmed != "" {
			cleanDomains = append(cleanDomains, trimmed)
		}
	}

	rule := s.pool.ruleManager.Add(req.Name, cleanDomains)
	// 异步对当前存活节点快速测活新规则并即时打标
	go s.pool.TestAndAddRuleToAlive(rule, 3*time.Second)
	w.Write([]byte(`{"status":"ok"}`))
}

func (s *StatusServer) handleDeleteRule(w http.ResponseWriter, r *http.Request) {
	w.Header().Set("Content-Type", "application/json")
	if !s.checkAuth(r) {
		w.WriteHeader(http.StatusUnauthorized)
		return
	}

	var req struct {
		Name string `json:"name"`
	}
	if err := json.NewDecoder(r.Body).Decode(&req); err != nil || req.Name == "" {
		w.WriteHeader(http.StatusBadRequest)
		return
	}

	s.pool.ruleManager.Delete(req.Name)
	s.pool.RemoveTagFromAllProxies(req.Name)
	w.Write([]byte(`{"status":"ok"}`))
}

func (s *StatusServer) handleRefresh(w http.ResponseWriter, r *http.Request) {
	w.Header().Set("Content-Type", "application/json")
	if !s.checkAuth(r) {
		w.WriteHeader(http.StatusUnauthorized)
		return
	}
	TriggerRefresh()
	w.Write([]byte(`{"status":"refresh triggered"}`))
}

func (s *StatusServer) handleSwitch(w http.ResponseWriter, r *http.Request) {
	w.Header().Set("Content-Type", "application/json")
	if !s.checkAuth(r) {
		w.WriteHeader(http.StatusUnauthorized)
		return
	}

	category := r.URL.Query().Get("category")
	if category == "" {
		category = "Default"
	}

	indexStr := r.URL.Query().Get("index")
	if indexStr != "" {
		index, err := strconv.Atoi(indexStr)
		if err != nil {
			w.WriteHeader(http.StatusBadRequest)
			return
		}
		s.pool.SwitchTo(category, index)
	} else {
		s.pool.SwitchNextForCategory(category)
	}
	w.Write([]byte(`{"status":"ok"}`))
}

func (s *StatusServer) handleDashboard(w http.ResponseWriter, r *http.Request) {
	w.Header().Set("Content-Type", "text/html; charset=utf-8")
	dashboardTmpl.Execute(w, nil)
}

var dashboardTmpl = template.Must(template.New("dashboard").Parse(`<!DOCTYPE html>
<html>
<head>
<meta charset="utf-8">
<title>Dashboard</title>
<meta name="viewport" content="width=device-width,initial-scale=1">
<style>
*{margin:0;padding:0;box-sizing:border-box}
body{font-family:system-ui,-apple-system,sans-serif;background:#0f172a;color:#e2e8f0;padding:12px}
.container{max-width:900px;margin:0 auto}
.btn{background:#38bdf8;color:#0f172a;border:none;padding:6px 14px;border-radius:6px;cursor:pointer;font-weight:bold;font-size:0.8rem}
.btn:hover{background:#7dd3fc}
.btn-sm{padding:2px 8px;font-size:0.75rem;border-radius:4px;cursor:pointer}
.btn-outline{background:transparent;border:1px solid #64748b;color:#94a3b8}
.btn-outline:hover{background:#334155;color:#fff}
.input-text{background:#0f172a;border:1px solid #475569;border-radius:6px;color:#fff;padding:6px 10px;font-size:0.85rem}
.tag{background:#334155;color:#94a3b8;font-size:0.75rem;padding:2px 6px;border-radius:4px}
.tag-active{background:rgba(74,222,128,0.2);color:#4ade80;border:1px solid #4ade80}
.grid{display:grid;grid-template-columns:repeat(auto-fit,minmax(150px,1fr));gap:8px;margin:10px 0}
.rule-card{background:#1e293b;border:1px solid #334155;border-radius:8px;padding:10px;position:relative}
.del-btn{position:absolute;right:6px;top:4px;background:transparent;border:none;color:#64748b;cursor:pointer;font-size:14px}
.del-btn:hover{color:#f87171}
.tab-bar{display:flex;gap:6px;overflow-x:auto;padding-bottom:6px;margin:10px 0}
.tab-btn{background:transparent;border:1px solid #334155;color:#94a3b8;padding:4px 12px;border-radius:6px;font-size:0.8rem;cursor:pointer}
.tab-btn.active{background:#38bdf8;color:#0f172a;border-color:#38bdf8;font-weight:bold}
.proxy-item{background:#1e293b;border:1px solid #334155;border-radius:8px;padding:10px 14px;margin:6px 0;display:flex;justify-content:space-between;align-items:center}
</style>
</head>
<body>
<div class="container">

  <!-- 极简匿名化登录卡片：防扫描特征识别 -->
  <div id="login-box" style="display:flex;justify-content:center;align-items:center;min-height:70vh">
    <div style="background:#1e293b;border:1px solid #334155;border-radius:8px;padding:20px;width:100%;max-width:300px;text-align:center">
      <div style="margin-bottom:12px">
        <input id="pwd-input" type="password" class="input-text" placeholder="Password" style="width:100%" onkeydown="if(event.key==='Enter')login()" />
      </div>
      <div id="login-err" style="display:none;color:#f87171;font-size:0.75rem;margin-bottom:8px">Invalid password</div>
      <button class="btn" style="width:100%" onclick="login()">进入</button>
    </div>
  </div>

  <!-- 管理主面板 -->
  <div id="main-panel" style="display:none">
    <div style="display:flex;justify-content:space-between;align-items:center;padding:10px 0;border-bottom:1px solid #334155">
      <div>
        <h2 style="font-size:1.1rem;color:#38bdf8;display:flex;align-items:center;gap:6px">
          SOCKS5 智能分流代理池
          <span style="font-size:0.75rem;background:rgba(74,222,128,0.2);color:#4ade80;border:1px solid #4ade80;padding:1px 6px;border-radius:4px">已认证</span>
        </h2>
        <div style="margin-top:4px;font-size:0.8rem;color:#94a3b8;display:flex;align-items:center;gap:6px">
          <span>公网接入点:</span>
          <span id="pub-endpoint" style="font-family:monospace;color:#38bdf8;background:#0f172a;padding:2px 6px;border-radius:4px">-</span>
          <button class="btn-sm btn-outline" onclick="copyEndpoint()">复制</button>
        </div>
      </div>
      <div style="display:flex;gap:8px">
        <button class="btn-sm btn" onclick="toggleAddRule()">+ 添加规则</button>
        <button class="btn-sm btn-outline" onclick="refreshPool()">刷新池</button>
        <button class="btn-sm btn-outline" onclick="logout()">退出</button>
      </div>
    </div>

    <div id="add-rule-form" style="display:none;background:#1e293b;border:1px solid #38bdf8;border-radius:8px;padding:12px;margin:10px 0">
      <div style="font-size:0.85rem;color:#38bdf8;font-weight:bold;margin-bottom:8px">添加自定义分流规则</div>
      <div style="display:flex;gap:8px;flex-wrap:wrap">
        <input id="new-rule-name" class="input-text" style="flex:1;min-width:120px" placeholder="规则名称 (如 abc)" />
        <input id="new-rule-domains" class="input-text" style="flex:2;min-width:200px" placeholder="匹配域名 (多个逗号隔开，如 abc.com,api.abc.com)" />
        <button class="btn" onclick="saveNewRule()">保存</button>
        <button class="btn-outline" style="padding:6px 10px;border-radius:6px;cursor:pointer" onclick="toggleAddRule()">取消</button>
      </div>
    </div>

    <div style="margin-top:14px">
      <div style="font-size:0.8rem;color:#94a3b8;font-weight:bold;text-transform:uppercase">各规则当前出口 (Active Outbounds)</div>
      <div id="rules-container" class="grid"></div>
    </div>

    <div class="tab-bar" id="tabs-container"></div>
    <div id="proxies-container"></div>
  </div>

</div>

<script>
var token = localStorage.getItem("admin_token") || "";
var cachedData = null;
var currentTab = "all";

function getHeaders() {
  return { "Authorization": "Bearer " + token, "Content-Type": "application/json" };
}

function login() {
  var p = document.getElementById("pwd-input").value;
  fetch("/api/auth", {
    method: "POST",
    headers: { "Content-Type": "application/json" },
    body: JSON.stringify({ password: p })
  }).then(function(res) {
    if (res.ok) {
      token = p;
      localStorage.setItem("admin_token", token);
      document.getElementById("login-box").style.display = "none";
      document.getElementById("main-panel").style.display = "block";
      loadStatus();
    } else {
      document.getElementById("login-err").style.display = "block";
    }
  }).catch(function() {
    document.getElementById("login-err").style.display = "block";
  });
}

function logout() {
  localStorage.removeItem("admin_token");
  token = "";
  document.getElementById("main-panel").style.display = "none";
  document.getElementById("login-box").style.display = "flex";
}

function copyEndpoint() {
  var text = document.getElementById("pub-endpoint").textContent;
  navigator.clipboard.writeText(text).then(function() { alert("已复制接入点: " + text); });
}

function loadStatus() {
  fetch("/api/status", { headers: getHeaders() })
    .then(function(r) {
      if (r.status === 401) { logout(); return null; }
      return r.json();
    })
    .then(function(data) {
      if (!data) return;
      cachedData = data;
      renderAll();
    });
}

function renderAll() {
  if (!cachedData) return;
  document.getElementById("pub-endpoint").textContent = cachedData.public_endpoint;

  var rBox = document.getElementById("rules-container");
  var outbounds = cachedData.active_outbounds || [];
  var rulesHtml = "";
  for (var i = 0; i < outbounds.length; i++) {
    var r = outbounds[i];
    rulesHtml += '<div class="rule-card">' +
      '<button class="del-btn" onclick="delRule(\'' + r.name + '\')" title="删除规则">&times;</button>' +
      '<div style="font-size:0.85rem;font-weight:bold;color:#38bdf8">' + r.name + ' <span style="font-size:0.75rem;color:#94a3b8">(' + r.count + ')</span></div>' +
      '<div style="font-family:monospace;font-size:0.8rem;color:#4ade80;margin:4px 0">' + r.active_ip + '</div>' +
      '<div style="font-size:0.75rem;color:#94a3b8;white-space:nowrap;overflow:hidden;text-overflow:ellipsis" title="' + r.location + '">' + r.location + '</div>' +
      '</div>';
  }
  rBox.innerHTML = rulesHtml;

  var tBox = document.getElementById("tabs-container");
  var tabsHtml = '<button class="tab-btn ' + (currentTab === "all" ? "active" : "") + '" onclick="setTab(\'all\')">全部 (' + cachedData.total + ')</button>';
  for (var j = 0; j < outbounds.length; j++) {
    var ob = outbounds[j];
    tabsHtml += '<button class="tab-btn ' + (currentTab === ob.name ? "active" : "") + '" onclick="setTab(\'' + ob.name + '\')">' + ob.name + ' (' + ob.count + ')</button>';
  }
  tBox.innerHTML = tabsHtml;

  var pBox = document.getElementById("proxies-container");
  var allProxies = cachedData.proxies || [];
  var filtered = [];
  for (var k = 0; k < allProxies.length; k++) {
    var px = allProxies[k];
    if (currentTab === "all") {
      filtered.push(px);
    } else if (px.tags && px.tags.indexOf(currentTab) !== -1) {
      filtered.push(px);
    }
  }

  if (filtered.length === 0) {
    pBox.innerHTML = '<div style="text-align:center;padding:30px;color:#64748b">暂无满足该条件的节点</div>';
    return;
  }

  var proxiesHtml = "";
  for (var m = 0; m < filtered.length; m++) {
    var p = filtered[m];
    var activeSpan = p.active ? '<span class="tag tag-active">ACTIVE: ' + p.active + '</span>' : '<span class="tag">STANDBY</span>';
    var tagsSpan = "";
    if (p.tags) {
      for (var n = 0; n < p.tags.length; n++) {
        tagsSpan += '<span class="tag">' + p.tags[n] + '</span>';
      }
    }
    proxiesHtml += '<div class="proxy-item">' +
      '<div>' +
      '<div style="display:flex;align-items:center;gap:6px">' +
      '<span style="font-family:monospace;font-size:0.85rem;font-weight:bold">' + p.addr + '</span>' +
      activeSpan +
      '</div>' +
      '<div style="font-size:0.75rem;color:#94a3b8;margin-top:2px">' + p.country + ' · ' + p.city + '</div>' +
      '</div>' +
      '<div style="display:flex;gap:4px;flex-wrap:wrap">' +
      tagsSpan +
      '</div>' +
      '</div>';
  }
  pBox.innerHTML = proxiesHtml;
}

function setTab(t) {
  currentTab = t;
  renderAll();
}

function toggleAddRule() {
  var f = document.getElementById("add-rule-form");
  f.style.display = f.style.display === "none" ? "block" : "none";
}

function saveNewRule() {
  var name = document.getElementById("new-rule-name").value.trim();
  var domains = document.getElementById("new-rule-domains").value.trim();
  if (!name || !domains) { alert("请填写名称和域名"); return; }

  fetch("/api/rules/add", {
    method: "POST",
    headers: getHeaders(),
    body: JSON.stringify({ name: name, domains: domains })
  }).then(function(r) { return r.json(); }).then(function() {
    document.getElementById("new-rule-name").value = "";
    document.getElementById("new-rule-domains").value = "";
    toggleAddRule();
    loadStatus();
    // 后台探测通常在 1~3 秒内完成，自动延时刷新展现新标签
    setTimeout(loadStatus, 1500);
    setTimeout(loadStatus, 3500);
  });
}

function delRule(name) {
  if (!confirm("确定删除分流规则 " + name + " 吗?")) return;
  fetch("/api/rules/delete", {
    method: "POST",
    headers: getHeaders(),
    body: JSON.stringify({ name: name })
  }).then(function(r) { return r.json(); }).then(function() {
    if (currentTab === name) currentTab = "all";
    loadStatus();
  });
}

function refreshPool() {
  fetch("/api/refresh", { method: "POST", headers: getHeaders() })
    .then(function() { alert("已触发重新抓取测活！"); });
}

if (token) {
  document.getElementById("login-box").style.display = "none";
  document.getElementById("main-panel").style.display = "block";
  loadStatus();
  setInterval(loadStatus, 15000);
}
</script>
</body>
</html>`))
