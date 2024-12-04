package main

import (
	"encoding/json"
	"fmt"
	"net/http"
	"net/url"
	"strings"
	"sync"
	"time"

	"golang.org/x/time/rate"
)

var apiKey string
var aclMutex sync.RWMutex

var rateLimiters = make(map[string]*rate.Limiter)
var rlMutex sync.Mutex

func getRateLimiter(ip string) *rate.Limiter {
	rlMutex.Lock()
	defer rlMutex.Unlock()

	if limiter, exists := rateLimiters[ip]; exists {
		return limiter
	}

	limiter := rate.NewLimiter(1, 5)
	rateLimiters[ip] = limiter

	go func() {
		time.Sleep(10 * time.Minute)
		rlMutex.Lock()
		delete(rateLimiters, ip)
		rlMutex.Unlock()
	}()

	return limiter
}

func rateLimitMiddleware(next http.Handler) http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		ip := r.RemoteAddr
		limiter := getRateLimiter(ip)

		if !limiter.Allow() {
			http.Error(w, "Too Many Requests", http.StatusTooManyRequests)
			return
		}
		next.ServeHTTP(w, r)
	})
}
func apiKeyMiddleware(next http.Handler) http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		key := r.Header.Get("X-API-KEY")
		if key != apiKey {
			http.Error(w, "Forbidden: Invalid API Key", http.StatusForbidden)
			return
		}
		next.ServeHTTP(w, r)
	})
}

func setupAPIRoutes(mux *http.ServeMux, proxyManager *ProxyManager, randApikey string) {
	if proxyManager == nil {
		logError("ProxyManager is not initialized. Cannot setup API routes.")
		return
	}
	apiKey = randApikey
	apiRouter := http.NewServeMux()

	apiRouter.HandleFunc("/api/proxies", func(w http.ResponseWriter, r *http.Request) {
		handleProxies(w, r, proxyManager)
	})
	apiRouter.HandleFunc("/api/ports", func(w http.ResponseWriter, r *http.Request) {
		handlePorts(w, r, proxyManager)
	})
	if aclConfig != nil {
		apiRouter.HandleFunc("/api/acl", func(w http.ResponseWriter, r *http.Request) {
			handleACLs(w, r, proxyManager)
		})
	}
	apiRouter.HandleFunc("/api/ban_session", handleBanSession)

	mux.Handle("/api/", rateLimitMiddleware(apiKeyMiddleware(apiRouter)))
}

func logAPIRequest(r *http.Request) {
	logInfo("API Request: Method=%s, Path=%s, IP=%s", r.Method, r.URL.Path, r.RemoteAddr)
}

func handleProxies(w http.ResponseWriter, r *http.Request, proxyManager *ProxyManager) {
	logAPIRequest(r)
	switch r.Method {
	case http.MethodGet:

		proxies := proxyManager.ListProxies()
		json.NewEncoder(w).Encode(proxies)

	case http.MethodPost:

		var proxyConfig struct {
			ID         string `json:"id"`
			Address    string `json:"address"`
			BackendURL string `json:"backend_url"`
		}
		if err := json.NewDecoder(r.Body).Decode(&proxyConfig); err != nil {
			http.Error(w, "Invalid request body", http.StatusBadRequest)
			return
		}
		proxyManager.AddProxy(proxyConfig.ID, proxyConfig.Address, proxyConfig.BackendURL)

		go StartProxyServer(proxyConfig.ID, proxyConfig.Address, proxyConfig.BackendURL, nil, false, proxyManager)
		w.WriteHeader(http.StatusCreated)

	case http.MethodDelete:

		id := r.URL.Query().Get("id")
		if id == "" {
			http.Error(w, "Missing proxy ID", http.StatusBadRequest)
			return
		}
		proxyManager.RemoveProxy(id)
		w.WriteHeader(http.StatusNoContent)

	default:
		http.Error(w, "Method not allowed", http.StatusMethodNotAllowed)
	}
}

func handlePorts(w http.ResponseWriter, r *http.Request, proxyManager *ProxyManager) {
	if r.Method != http.MethodPost {
		http.Error(w, "Method not allowed", http.StatusMethodNotAllowed)
		return
	}

	var ports []string
	if err := json.NewDecoder(r.Body).Decode(&ports); err != nil {
		http.Error(w, "Invalid request body", http.StatusBadRequest)
		return
	}

	proxyManager.UpdatePorts(ports)
	w.WriteHeader(http.StatusOK)
}

func (pm *ProxyManager) ListProxies() []string {
	if pm == nil {
		logError("ProxyManager is nil")
		return nil
	}

	var proxyList []string
	for _, proxy := range pm.proxies {
		proxyList = append(proxyList, proxy.String())
	}
	return proxyList
}

func (pm *ProxyManager) AddProxy(id, address, backendURL string) {
	newBackend, err := url.Parse(backendURL)
	if err != nil {
		logError("Failed to parse backend URL: %v", err)
		return
	}

	publicProxyURL := fmt.Sprintf("https://%s%s", getServerIPAddress(), address)
	newPublicProxy, err := url.Parse(publicProxyURL)
	if err != nil {
		logError("Failed to parse public proxy URL: %v", err)
		return
	}

	pm.mu.Lock()
	defer pm.mu.Unlock()
	for _, proxy := range pm.proxies {
		if proxy.String() == newPublicProxy.String() {
			logWarning("Proxy %s already exists; skipping addition", newPublicProxy.String())
			return
		}
	}
	pm.proxies = append(pm.proxies, newPublicProxy)
	logInfo("Added new proxy: %s (%s -> %s)", id, publicProxyURL, newBackend)
}

func (pm *ProxyManager) RemoveProxy(proxyID string) {
	pm.mu.Lock()
	defer pm.mu.Unlock()

	for i, proxy := range pm.proxies {
		if strings.Contains(proxy.String(), proxyID) {
			pm.proxies = append(pm.proxies[:i], pm.proxies[i+1:]...)
			logInfo("Proxy %s removed successfully", proxyID)
			return
		}
	}
	logWarning("Proxy %s not found; nothing removed", proxyID)
}

func (pm *ProxyManager) UpdatePorts(ports []string) {
	if len(ports) != len(pm.proxies) {
		logWarning("Number of ports does not match number of proxies")
		return
	}

	for i, proxy := range pm.proxies {
		host := strings.Split(proxy.Host, ":")[0]
		pm.proxies[i].Host = fmt.Sprintf("%s:%s", host, ports[i])
	}

	logInfo("Updated proxy ports: %v", ports)
}

// handleACLs manages ACL rules.
func handleACLs(w http.ResponseWriter, r *http.Request, proxyManager *ProxyManager) {
	logAPIRequest(r)
	switch r.Method {
	case http.MethodGet:
		getACLHandler(w)
	case http.MethodPost:
		addACLHandler(w, r, proxyManager)
	case http.MethodPut:
		modifyACLHandler(w, r, proxyManager)
	case http.MethodDelete:
		deleteACLHandler(w, r, proxyManager)
	default:
		http.Error(w, "Method not allowed", http.StatusMethodNotAllowed)
	}
}

// ReloadACLConfig apply ACL rules to all proxies.
func ReloadACLConfig() {
	aclMutex.Lock()
	defer aclMutex.Unlock()

	logInfo("Reloaded global ACL rules.")
}

// getACLHandler return ACL rules.
func getACLHandler(w http.ResponseWriter) {
	aclMutex.RLock()
	defer aclMutex.RUnlock()

	w.Header().Set("Content-Type", "application/json")

	normalizedRules, err := normalizeACLRules(aclConfig.Rules)
	if err != nil {
		logError("Failed to normalize ACL rules: %v", err)
		http.Error(w, "Failed to process ACL rules", http.StatusInternalServerError)
		return
	}

	if err := json.NewEncoder(w).Encode(normalizedRules); err != nil {
		logError("Failed to encode ACL rules: %v", err)
		http.Error(w, "Failed to encode ACL rules", http.StatusInternalServerError)
	}
}

func addACLHandler(w http.ResponseWriter, r *http.Request, proxyManager *ProxyManager) {
	var requestData struct {
		Rule     ACLRule `json:"rule"`
		Priority int     `json:"priority,omitempty"`
	}

	if err := json.NewDecoder(r.Body).Decode(&requestData); err != nil {
		http.Error(w, "Invalid input", http.StatusBadRequest)
		return
	}

	priority := requestData.Priority
	if priority < 0 {
		priority = 0
	}

	aclConfig.AddRuleWithPriority(requestData.Rule, priority)
	ReloadACL()
	ApplyACLToProxies(proxyManager)

	w.WriteHeader(http.StatusCreated)
	json.NewEncoder(w).Encode(map[string]string{"message": "ACL rule added successfully"})
}

// modifyACLHandler modify an existing ACL rule.
func modifyACLHandler(w http.ResponseWriter, r *http.Request, proxyManager *ProxyManager) {
	ruleName := r.URL.Query().Get("name")
	if ruleName == "" {
		http.Error(w, "Missing ACL rule name", http.StatusBadRequest)
		return
	}

	var updatedRule ACLRule
	if err := json.NewDecoder(r.Body).Decode(&updatedRule); err != nil {
		http.Error(w, "Invalid input", http.StatusBadRequest)
		return
	}

	aclConfig.UpdateRule(updatedRule)
	ReloadProxiesWithACLConfig(proxyManager, aclConfig)

	w.WriteHeader(http.StatusOK)
	json.NewEncoder(w).Encode(map[string]string{"message": "ACL rule updated successfully"})
}

// deleteACLHandler delete an ACL rule.
func deleteACLHandler(w http.ResponseWriter, r *http.Request, proxyManager *ProxyManager) {
	ruleName := r.URL.Query().Get("name")
	if ruleName == "" {
		http.Error(w, "Missing ACL rule name", http.StatusBadRequest)
		return
	}

	aclConfig.RemoveRule(ruleName)
	ReloadProxiesWithACLConfig(proxyManager, aclConfig)

	w.WriteHeader(http.StatusOK)
	json.NewEncoder(w).Encode(map[string]string{"message": "ACL rule deleted successfully"})
}

func normalizeACLRules(rules []ACLRule) ([]map[string]interface{}, error) {
	var normalizedRules []map[string]interface{}
	for _, rule := range rules {
		normalizedRule := map[string]interface{}{
			"name":      rule.Name,
			"condition": rule.Condition,
			"value":     normalizeValue(rule.Value),
			"action":    rule.Action,
			"options":   rule.Options,
		}
		normalizedRules = append(normalizedRules, normalizedRule)
	}
	return normalizedRules, nil
}

func normalizeValue(value interface{}) interface{} {
	switch v := value.(type) {
	case map[interface{}]interface{}:
		normalizedMap := make(map[string]interface{})
		for key, val := range v {
			normalizedMap[fmt.Sprintf("%v", key)] = val
		}
		return normalizedMap
	case string:
		return v
	default:
		return fmt.Sprintf("%v", v)
	}
}

func handleBanSession(w http.ResponseWriter, r *http.Request) {
	sessionID := r.URL.Query().Get("session_id")
	if sessionID == "" {
		http.Error(w, "Missing session_id", http.StatusBadRequest)
		return
	}

	BlacklistSession(sessionID)
	w.WriteHeader(http.StatusOK)
	json.NewEncoder(w).Encode(map[string]string{"message": "Session blacklisted successfully"})
}
