package main

import (
	"encoding/json"
	"log"
	"os"
	"strings"
	"sync"
)

type RouteRule struct {
	ID      string   `json:"id"`
	Name    string   `json:"name"`
	Domains []string `json:"domains"`
}

type RuleManager struct {
	mu       sync.RWMutex
	rules    []RouteRule
	filePath string
}

func NewRuleManager(filePath string) *RuleManager {
	rm := &RuleManager{
		filePath: filePath,
	}
	rm.load()
	return rm
}

func (rm *RuleManager) defaultRules() []RouteRule {
	return []RouteRule{
		{
			ID:      "rule_openai",
			Name:    "OpenAI",
			Domains: []string{"openai.com", "ai.com", "oaistatic.com"},
		},
		{
			ID:      "rule_gemini",
			Name:    "Gemini",
			Domains: []string{"googleapis.com", "google.com"},
		},
		{
			ID:      "rule_anthropic",
			Name:    "Anthropic",
			Domains: []string{"anthropic.com", "claude.ai"},
		},
		{
			ID:      "rule_grok",
			Name:    "Grok",
			Domains: []string{"x.ai", "grok.com", "twitter.com", "x.com"},
		},
	}
}

func (rm *RuleManager) load() {
	rm.mu.Lock()
	defer rm.mu.Unlock()

	data, err := os.ReadFile(rm.filePath)
	if err != nil {
		rm.rules = rm.defaultRules()
		rm.saveLocked()
		return
	}

	var rules []RouteRule
	if err := json.Unmarshal(data, &rules); err != nil || len(rules) == 0 {
		rm.rules = rm.defaultRules()
		rm.saveLocked()
		return
	}

	rm.rules = rules
	log.Printf("[rule] 已加载 %d 条分流规则", len(rm.rules))
}

func (rm *RuleManager) saveLocked() {
	data, err := json.MarshalIndent(rm.rules, "", "  ")
	if err != nil {
		return
	}
	_ = os.WriteFile(rm.filePath, data, 0644)
}

func (rm *RuleManager) All() []RouteRule {
	rm.mu.RLock()
	defer rm.mu.RUnlock()
	res := make([]RouteRule, len(rm.rules))
	copy(res, rm.rules)
	return res
}

func (rm *RuleManager) Add(name string, domains []string) RouteRule {
	rm.mu.Lock()
	defer rm.mu.Unlock()

	name = strings.TrimSpace(name)
	for i, r := range rm.rules {
		if strings.EqualFold(r.Name, name) {
			rm.rules[i].Domains = domains
			rm.saveLocked()
			return rm.rules[i]
		}
	}

	rule := RouteRule{
		ID:      "rule_" + strings.ToLower(name),
		Name:    name,
		Domains: domains,
	}
	rm.rules = append(rm.rules, rule)
	rm.saveLocked()
	log.Printf("[rule] 新增/更新规则: %s -> %v", name, domains)
	return rule
}

func sameDomains(a, b []string) bool {
	if len(a) != len(b) {
		return false
	}
	seen := make(map[string]bool)
	for _, v := range a {
		seen[strings.ToLower(strings.TrimSpace(v))] = true
	}
	for _, v := range b {
		if !seen[strings.ToLower(strings.TrimSpace(v))] {
			return false
		}
	}
	return true
}

func (rm *RuleManager) Update(oldName, newName string, domains []string) (RouteRule, bool, bool) {
	rm.mu.Lock()
	defer rm.mu.Unlock()

	oldName = strings.TrimSpace(oldName)
	newName = strings.TrimSpace(newName)
	for i, r := range rm.rules {
		if strings.EqualFold(r.Name, oldName) {
			domainsChanged := !sameDomains(rm.rules[i].Domains, domains)
			rm.rules[i].Name = newName
			rm.rules[i].Domains = domains
			rm.rules[i].ID = "rule_" + strings.ToLower(newName)
			rm.saveLocked()
			log.Printf("[rule] 更新规则: %s -> %s %v (域名变动: %v)", oldName, newName, domains, domainsChanged)
			return rm.rules[i], domainsChanged, true
		}
	}
	return RouteRule{}, false, false
}

func (rm *RuleManager) Delete(name string) bool {
	rm.mu.Lock()
	defer rm.mu.Unlock()

	for i, r := range rm.rules {
		if strings.EqualFold(r.Name, name) {
			rm.rules = append(rm.rules[:i], rm.rules[i+1:]...)
			rm.saveLocked()
			log.Printf("[rule] 删除规则: %s", name)
			return true
		}
	}
	return false
}

// Match 根据目标 host 匹配对应的规则名称；若无匹配则返回 "Default"
func (rm *RuleManager) Match(targetHost string) string {
	rm.mu.RLock()
	defer rm.mu.RUnlock()

	host := strings.ToLower(strings.TrimSpace(targetHost))

	for _, rule := range rm.rules {
		for _, domain := range rule.Domains {
			d := strings.ToLower(strings.TrimSpace(domain))
			if d == "" {
				continue
			}
			if host == d || strings.HasSuffix(host, "."+d) || strings.Contains(host, d) {
				return rule.Name
			}
		}
	}

	return "Default"
}
