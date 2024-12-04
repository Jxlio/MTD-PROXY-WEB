package main

import (
	"bytes"
	"compress/gzip"
	"context"
	"crypto/tls"
	"io"
	"log"
	"net/http"
	"net/http/httputil"
	"net/url"
	"os"
	"strings"
	"sync"
	"time"

	"github.com/go-redis/redis/v8"
	"golang.org/x/exp/rand"
)

// startAutoSwitch switches proxies automatically every 10 seconds
func (pm *ProxyManager) startAutoSwitch() {
	for range pm.ticker.C {
		pm.switchProxy()
	}
}

// switchProxy switches to the next proxy in the list
func (pm *ProxyManager) switchProxy() {
	pm.mu.Lock()
	defer pm.mu.Unlock()

	rand.Shuffle(len(pm.proxies), func(i, j int) {
		pm.proxies[i], pm.proxies[j] = pm.proxies[j], pm.proxies[i]
	})

	pm.currentProxy = pm.proxies[0]
	logInfo("Switched to new proxy: %s", pm.currentProxy)

	proxySwitchesTotal.WithLabelValues(pm.currentProxy.String()).Inc()

	pm.UpdateActiveProxy(pm.currentProxy)
}

// GetProxy returns the current proxy
func (pm *ProxyManager) GetProxy() *url.URL {
	logInfo("Fetching current proxy: %s", pm.currentProxy)

	pm.mu.Lock()
	defer pm.mu.Unlock()
	return pm.currentProxy
}

// UpdateActiveProxy updates the active proxy in Redis
func (pm *ProxyManager) UpdateActiveProxy(currentProxy *url.URL) {
	redisClient := redis.NewClient(&redis.Options{
		Addr: "localhost:6379",
	})
	defer redisClient.Close()

	err := redisClient.Set(ctx, "active_proxy", currentProxy.String(), 0).Err()
	if err != nil {
		logError("Failed to update active proxy in Redis: %v", err)
	} else {
		logSuccess("Successfully updated active proxy to %s in Redis", currentProxy.String())
	}

	err = redisClient.Publish(ctx, "proxy_updates", currentProxy.String()).Err()
	if err != nil {
		logError("Failed to publish proxy update: %v", err)
	}
}

// GetActiveProxy retrieves the currently active proxy from Redis
func (pm *ProxyManager) GetActiveProxy() (*url.URL, error) {
	redisClient := redis.NewClient(&redis.Options{
		Addr: "localhost:6379",
	})
	defer redisClient.Close()

	activeProxyStr, err := redisClient.Get(ctx, "active_proxy").Result()
	if err != nil {
		logError("Error fetching active proxy from Redis: %v", err)
	}
	if err != nil {
		return nil, err
	}

	activeProxy, err := url.Parse(activeProxyStr)
	if err != nil {
		return nil, err
	}

	return activeProxy, nil
}

func getNewProxyURL() string {
	return currentProxyURL
}

// StartProxyServer starts a proxy server on the given address and forwards requests to the backendURL.
func StartProxyServer(proxyID, address, backendURL string, queue *Queue, enableDetection bool, pm *ProxyManager) {
	parsedURL, err := url.Parse(backendURL)
	if err != nil {
		log.Fatalf("Failed to parse backend URL: %v", err)
	}

	redisClient = redis.NewClient(&redis.Options{
		Addr: "localhost:6379",
	})

	proxy := httputil.NewSingleHostReverseProxy(parsedURL)
	EnableSkipSecureVerify(proxy)
	originalDirector := proxy.Director
	if queue == nil {
		proxy.Director = originalDirector
	} else {
		proxy.Director = func(req *http.Request) {
			originalDirector(req)
			req.Header.Add("X-Proxy-ID", proxyID)

			messages, err := queue.client.XReadGroup(ctx, &redis.XReadGroupArgs{
				Group:    "proxy_group",
				Consumer: "proxy_consumer",
				Streams:  []string{"proxy_requests", ">"},
				Count:    1,
				Block:    10 * time.Millisecond,
			}).Result()

			if err != nil {
				return
			}

			for _, msg := range messages[0].Messages {
				if msg.Values["block"] == "true" {
					req.URL.Host = ""
					logInfo("Blocked request based on queue message")
				}
				if newURL, ok := msg.Values["redirect_url"].(string); ok {
					parsedNewURL, _ := url.Parse(newURL)
					req.URL.Scheme = parsedNewURL.Scheme
					req.URL.Host = parsedNewURL.Host
					req.URL.Path = parsedNewURL.Path
					logInfo("Redirected request to new URL: %s", newURL)
				}
			}
		}
	}

	proxy.ModifyResponse = func(resp *http.Response) error {
		applyHeaderRules(resp)

		if strings.Contains(resp.Header.Get("Content-Encoding"), "gzip") {
			logInfo("Skipping Gzip compression; response already compressed")
			return nil
		}

		if strings.Contains(resp.Request.Header.Get("Accept-Encoding"), "gzip") {
			logInfo("Applying Gzip compression from ModifyResponse to response for URL: %s", resp.Request.URL)

			resp.Header.Set("Content-Encoding", "gzip")
			resp.Header.Del("Content-Length")

			var buf bytes.Buffer
			gz := gzip.NewWriter(&buf)
			_, err := io.Copy(gz, resp.Body)
			if err != nil {
				resp.Body.Close()
				logError("Error during Gzip compression: %v", err)
				return err
			}
			gz.Close()

			resp.Body.Close()
			resp.Body = io.NopCloser(&buf)
			resp.ContentLength = -1

			logSuccess("Gzip compression applied successfully for URL: %s", resp.Request.URL)
		}

		return nil
	}

	var requestCounts = make(map[string]int)
	var mu sync.Mutex
	mux := http.NewServeMux()

	mux.HandleFunc("/health", func(w http.ResponseWriter, r *http.Request) {
		w.WriteHeader(http.StatusOK)
		w.Write([]byte("Proxy is healthy"))
	})

	activeProxy, err := redisClient.Get(ctx, "active_proxy").Result()
	if err != nil {
		logError("Failed to get active proxy: %v", err)
		activeProxy = "https://localhost"
	}
	currentProxyURL = activeProxy

	mux.Handle("/", SessionMiddleware(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {

		start := time.Now()
		status := "200"

		defer func() {
			duration := time.Since(start).Seconds()
			proxyRequestsTotal.WithLabelValues(proxyID, status, r.Method).Inc()
			proxyRequestDuration.WithLabelValues(proxyID, r.Method).Observe(duration)
		}()
		logRequest(r)
		mu.Lock()
		defer mu.Unlock()

		ip := r.RemoteAddr
		requestCounts[ip]++

		if requestCounts[ip] > 500 {
			status = "429"
			http.Error(w, "Too Many Requests", http.StatusTooManyRequests)
			return
		}

		logInfo("%s received : %s", proxyID, r.URL.String())

		activeProxy, err := redisClient.Get(ctx, "active_proxy").Result()
		if err != nil {
			logError("Failed to get active proxy: %v", err)
			status = "500"
			http.Error(w, "Internal Server Error", http.StatusInternalServerError)
			return
		}

		if "https://"+r.Host != activeProxy {
			status = "302"
			http.Redirect(w, r, activeProxy+r.RequestURI, http.StatusFound)
			return
		}

		bodyBytes, err := io.ReadAll(r.Body)
		if err != nil {
			status = "500"
			http.Error(w, "Failed to read request body", http.StatusInternalServerError)
			return
		}
		r.Body = io.NopCloser(bytes.NewReader(bodyBytes))

		if enableDetection {

			detectionData := map[string]interface{}{
				"uri":  r.RequestURI,
				"body": string(bodyBytes),
			}
			detectionResponse, err := sendToDetectionService(detectionData)
			if err != nil {
				status = "500"
				http.Error(w, "Failed to connect to detection service", http.StatusInternalServerError)
				return
			}

			if detectionResponse["authorized"] == "MALICIOUS" {
				status = "403"
				htmlContent, err := os.ReadFile("403.html")
				if err != nil {
					status = "500"
					http.Error(w, "Failed to load 403 page", http.StatusInternalServerError)
					return
				}
				w.Header().Set("Content-Type", "text/html")
				w.WriteHeader(http.StatusForbidden)
				w.Write(htmlContent)
				return
			}
		}
		if aclConfig != nil {
			logInfo("list rule : %v", aclConfig.Rules)
			if handled := HandleRequestWithACL(r, w, aclConfig); handled {
				return
			}
		}
		proxy.ServeHTTP(w, r)

	})))

	go func() {
		pubsub := redisClient.Subscribe(ctx, "proxy_updates")
		defer pubsub.Close()

		for msg := range pubsub.Channel() {
			logInfo("Received new proxy update: %s", msg.Payload)
			currentProxyURL = msg.Payload
		}
	}()

	server := &http.Server{
		Addr:    "0.0.0.0" + address,
		Handler: mux,
		TLSConfig: &tls.Config{
			MinVersion: tls.VersionTLS12,
		},
	}

	logInfo("Starting HTTPS proxy server %s on %s", proxyID, address)
	server.ListenAndServeTLS("server.crt", "server.key")
}

// ReloadProxiesWithACLConfig reloads all proxies with the updated ACL configuration
func ReloadProxiesWithACLConfig(proxyManager *ProxyManager, aclConfig *ACLConfig) {
	proxyManager.mu.Lock()
	defer proxyManager.mu.Unlock()

	for _, proxy := range proxyManager.proxies {
		logInfo("Reloading ACL config for proxy: %s", proxy.String())
	}
	logInfo("All proxies reloaded with updated ACL configuration")
}

func ApplyACLToProxies(pm *ProxyManager) {
	pm.mu.Lock()
	defer pm.mu.Unlock()

	for _, proxy := range pm.proxies {
		logInfo("Applying ACL rules to proxy: %s", proxy.String())
	}
}

func SessionMiddleware(next http.Handler) http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		sessionID, err := GetSessionID(r)
		clientIP := r.RemoteAddr

		if err != nil || sessionID == "" {
			sessionID = generateSessionID()
			token, err := GenerateJWT(sessionID, clientIP)
			if err != nil {
				if err.Error() == "rate limit exceeded for IP "+clientIP {
					http.Error(w, "Too many JWT generations. Try again later.", http.StatusTooManyRequests)
					return
				}
				http.Error(w, "Failed to generate session token", http.StatusInternalServerError)
				return
			}
			SetSessionCookie(w, token)
		}

		if IsSessionBlacklisted(sessionID) {
			http.Error(w, "Forbidden: Your session is blacklisted", http.StatusForbidden)
			return
		}

		ctx := context.WithValue(r.Context(), "sessionID", sessionID)
		next.ServeHTTP(w, r.WithContext(ctx))
	})
}
