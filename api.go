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
