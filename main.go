package main

import (
	"context"
	"crypto/tls"
	"flag"
	"net/http"
	"net/http/httputil"
	"net/url"
	"strings"
	"time"

	"github.com/prometheus/client_golang/prometheus"
	"github.com/prometheus/client_golang/prometheus/promhttp"
)

var ctx = context.Background()

// Metrics for Prometheus monitoring
var (
	proxyRequestsTotal = prometheus.NewCounterVec(
		prometheus.CounterOpts{
			Name: "proxy_requests_total",
			Help: "Total number of requests handled by each proxy",
		},
		[]string{"proxy_id", "status", "method"},
	)
	proxyRequestDuration = prometheus.NewHistogramVec(
		prometheus.HistogramOpts{
			Name:    "proxy_request_duration_seconds",
			Help:    "Histogram of request durations per proxy",
			Buckets: prometheus.DefBuckets,
		},
		[]string{"proxy_id", "method"},
	)
)
var proxySwitchesTotal = prometheus.NewCounterVec(
	prometheus.CounterOpts{
		Name: "proxy_switches_total",
		Help: "Total number of proxy switches",
	},
	[]string{"proxy_id"},
)

func init() {
	prometheus.MustRegister(proxyRequestsTotal, proxyRequestDuration)
	prometheus.MustRegister(proxySwitchesTotal)
}

func NewProxyManager(proxyURLs []string) *ProxyManager {
	proxies := make([]*url.URL, len(proxyURLs))
	for i, proxyURL := range proxyURLs {
		url, err := url.Parse(proxyURL)
		if err != nil {
			logError("Invalid proxy URL: %s", proxyURL)
		}
		proxies[i] = url
	}

	pm := &ProxyManager{
		proxies:      proxies,
		currentProxy: proxies[0],                       // Commence avec le premier proxy
		ticker:       time.NewTicker(10 * time.Second), // Change toutes les 10 secondes
	}

	go pm.startAutoSwitch() // Démarre le changement automatique de proxy

	return pm
}

// ServeHTTP dynamically proxies the request through one of the managed proxies
func (pm *ProxyManager) ServeHTTP(w http.ResponseWriter, r *http.Request) {
	start := time.Now()
	status := "200"

	defer func() {
		duration := time.Since(start).Seconds()

		// Ajoute la valeur manquante pour le label proxy_id
		proxyID := pm.GetProxy().String()

		proxyRequestsTotal.WithLabelValues(proxyID, status, r.Method).Inc()
		proxyRequestDuration.WithLabelValues(proxyID, r.Method).Observe(duration)
	}()

	// Obtenir l'URL du proxy actif depuis Redis
	activeProxy, err := pm.GetActiveProxy()
	if err != nil {
		status = "500"
		http.Error(w, "Internal Server Error", http.StatusInternalServerError)
		return
	}

	// Vérifie si l'URL demandée correspond à l'URL du proxy actif
	requestedURL := r.URL
	activeProxyURL := pm.GetProxy()

	if requestedURL.Scheme != activeProxyURL.Scheme || strings.Split(requestedURL.Host, ":")[0] != strings.Split(activeProxyURL.Host, ":")[0] {
		http.Redirect(w, r, activeProxyURL.String()+r.RequestURI, http.StatusTemporaryRedirect)
		return
	}
	// Proxy la requête au proxy courant
	proxy := httputil.NewSingleHostReverseProxy(activeProxy)
	proxy.Transport = &http.Transport{
		TLSClientConfig: &tls.Config{
			InsecureSkipVerify: true, // Ignore les erreurs de certificat
		},
	}
	proxy.ServeHTTP(w, r)
}

func main() {
	ServerIPArg := flag.String("ip", "", "Define the Public IP address of the proxies")
	headerRulesFile := flag.String("header-rules", "", "Path to the header rules YAML file")
	verbose := flag.Bool("v", false, "Enable verbose logging to the terminal")
	queueSystem := flag.Bool("queue-system", false, "Queue system to use (redis or kafka)")
	enableDetection := flag.Bool("enable-detection", false, "Enable or disable the attack detection system") // Nouvel argument
	flag.Parse()

	var serverIP string
	configureLogger(*verbose)

	if *ServerIPArg != "" {
		logInfo("IP address %s has been manually set", *ServerIPArg)
		serverIP = *ServerIPArg
	} else {
		serverIP = getServerIPAddress()
		logWarning("No IP address specified. Using %s as the server IP address", serverIP)
	}

	// Charger les règles d'en-têtes si le fichier est spécifié
	if *headerRulesFile != "" {
		logInfo("Loading header rules from %s", *headerRulesFile)
		headerRules = loadHeaderRules(*headerRulesFile)
	} else {
		logWarning("No header rules specified. Header modification is disabled.")
	}

	// Initialiser la queue si activée
	if *queueSystem {
		queue := NewQueue("localhost:6379", "proxy_requests", "proxy_group")
		if err := ensureQueueSetup(queue); err != nil {
			logError("Failed to setup queue: %v", err)
		}
		addTestMessage(queue)
		go startConsumers(queue)
	}

	// Proxy configurations
	proxyConfigs := []struct {
		id         string
		address    string
		backendURL string
	}{
		{id: "proxy1", address: ":8081", backendURL: "http://127.0.0.1:5000"},
		{id: "proxy2", address: ":8082", backendURL: "http://127.0.0.1:5000"},
		{id: "proxy3", address: ":8083", backendURL: "http://127.0.0.1:5000"},
		{id: "proxy4", address: ":8084", backendURL: "http://127.0.0.1:5000"},
	}

	if *queueSystem {
		queue := NewQueue("localhost:6379", "proxy_requests", "proxy_group")
		for _, config := range proxyConfigs {
			go StartProxyServer(config.id, config.address, config.backendURL, queue)
		}
	} else {
		for _, config := range proxyConfigs {
			go StartProxyServer(config.id, config.address, config.backendURL, nil)
		}
	}

	proxyURLs := []string{
		"https://" + serverIP + ":8081",
		"https://" + serverIP + ":8082",
		"https://" + serverIP + ":8083",
		"https://" + serverIP + ":8084",
	}

	proxyManager := NewProxyManager(proxyURLs)
	var suspiciousRating *SuspiciousRating
	if *enableDetection {
		logInfo("Attack detection system enabled")
		suspiciousRating = NewSuspiciousRating("localhost:6379", 20)
	} else {
		logInfo("Attack detection system disabled")
	}

	// Setup Prometheus metrics endpoint
	http.Handle("/metrics", promhttp.Handler())

	// Handle incoming requests
	http.HandleFunc("/", func(w http.ResponseWriter, r *http.Request) {
		if *enableDetection && suspiciousRating != nil {
			ip := r.RemoteAddr
			if suspiciousRating.DetectAttack(r) {
				suspiciousRating.UpdateRating(ip, 5)
			}
			rating := suspiciousRating.GetRating(ip)
			if rating > suspiciousRating.maxSuspicion {
				http.Error(w, "Forbidden", http.StatusForbidden)
				return
			}
			suspiciousRating.UpdateRating(ip, 1)
		}
		logRequest(r)
		proxyManager.ServeHTTP(w, r)
	})

	server := &http.Server{
		Addr:         "0.0.0.0:443",
		Handler:      nil,
		ReadTimeout:  10 * time.Second,
		WriteTimeout: 10 * time.Second,
		IdleTimeout:  60 * time.Second,
		TLSConfig: &tls.Config{
			MinVersion: tls.VersionTLS12,
		},
	}

	logInfo("Starting HTTP to HTTPS redirect server on :80")
	server.ListenAndServeTLS("server.crt", "server.key")
}

func startConsumers(queue *Queue) {
	for {
		messages, err := queue.ConsumeFromQueue("consumer1", 10, 5*time.Second)
		if err != nil {
			continue
		}
		for _, message := range messages {
			// Traitez le message ici
			logInfo("Processing message: %v", message.Values)
			// Accuser réception du message
			err := queue.AckMessage(message.ID)
			if err != nil {
				logError("Failed to acknowledge message: %v", err)
			}
		}
	}
}
