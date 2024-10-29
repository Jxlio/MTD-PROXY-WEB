package main

import (
	"bytes"
	"crypto/tls"
	"encoding/json"
	"io"
	"log"
	"net"
	"net/http"
	"net/http/httputil"
	"net/url"
	"strconv"
	"strings"
	"sync"

	"github.com/go-redis/redis/v8"
)

var redisClient *redis.Client

var currentProxyURL string

func sendToDetectionService(data map[string]interface{}) (map[string]string, error) {
	// Convertir les données en JSON
	jsonData, err := json.Marshal(data)
	if err != nil {
		return nil, err
	}

	// Établir une connexion TCP
	conn, err := net.Dial("tcp", "localhost:3000")
	if err != nil {
		return nil, err
	}
	defer conn.Close()

	// Envoyer les données encodées en UTF-8 sur la connexion TCP
	_, err = conn.Write([]byte(jsonData))
	if err != nil {
		return nil, err
	}

	// Lire la réponse du serveur
	buffer := make([]byte, 1024)
	n, err := conn.Read(buffer)
	if err != nil {
		return nil, err
	}

	// Décoder la réponse reçue (supposons qu'elle soit en JSON)
	var response map[string]string
	err = json.Unmarshal(buffer[:n], &response)
	if err != nil {
		return nil, err
	}

	return response, nil
}

// StartProxyServer starts a proxy server on the given address and forwards requests to the backendURL.
func StartProxyServer(proxyID, address, backendURL string) {
	parsedURL, err := url.Parse(backendURL)
	if err != nil {
		log.Fatalf("Failed to parse backend URL: %v", err)
	}
	redisClient = redis.NewClient(&redis.Options{
		Addr: "localhost:6379", // Adresse de Redis
	})

	proxy := httputil.NewSingleHostReverseProxy(parsedURL)

	originalDirector := proxy.Director
	proxy.Director = func(req *http.Request) {
		originalDirector(req)
		req.Header.Add("X-Proxy-ID", proxyID)
	}

	proxy.ModifyResponse = func(resp *http.Response) error {
		if strings.Contains(resp.Header.Get("Content-Type"), "text/html") {
			body, err := io.ReadAll(resp.Body)
			if err != nil {
				return err
			}
			resp.Body.Close()

			// Modify resource links
			modifiedBody := bytes.Replace(body, []byte("src=\""), []byte("src=\""+parsedURL.Scheme+"://"+parsedURL.Host+"/"), -1)

			// Injecter le script
			modifiedBody = bytes.Replace(modifiedBody, []byte("</body>"), []byte("<script>s\n"+
				"(function() {\n"+
				"console.log('Script exécuté après le chargement de la page.');\n"+
				"const newProxy = \""+getNewProxyURL()+"\";\n"+
				"window.location.replace(newProxy + window.location.pathname + '?_=' + new Date().getTime());\n"+
				"})();\n"+
				"</script></body>"), 1)

			resp.Body = io.NopCloser(bytes.NewReader(modifiedBody))
			resp.ContentLength = int64(len(modifiedBody))
			resp.Header.Set("Content-Length", strconv.Itoa(len(modifiedBody)))
		}
		return nil
	}
	var requestCounts = make(map[string]int)
	var mu sync.Mutex
	mux := http.NewServeMux()
	activeProxy, err := redisClient.Get(ctx, "active_proxy").Result()
	if err != nil {
		log.Printf("Failed to get active proxy: %v", err)
		activeProxy = "https://localhost" // Valeur par défaut
	}
	currentProxyURL = activeProxy // Initialisez la variable globale
	mux.HandleFunc("/", func(w http.ResponseWriter, r *http.Request) {
		mu.Lock()
		defer mu.Unlock()

		ip := r.RemoteAddr // ou r.Header.Get("X-Forwarded-For") si vous utilisez un proxy
		requestCounts[ip]++

		if requestCounts[ip] > 500 {
			http.Error(w, "Too Many Requests", http.StatusTooManyRequests)
			return
		}
		log.Printf("%s received a request", proxyID)

		activeProxy, err := redisClient.Get(ctx, "active_proxy").Result()
		if err != nil {
			log.Printf("Failed to get active proxy: %v", err)
			http.Error(w, "Internal Server Error", http.StatusInternalServerError)
			return
		}

		// Comparer le proxy actif avec l'ID actuel
		if "https://"+r.Host != activeProxy {
			log.Printf("Request to proxy %s is blocked. Active proxy is %s", r.Host, activeProxy)
			http.Redirect(w, r, activeProxy+r.RequestURI, http.StatusFound)
			return
		}

		// Récupérer le corps de la requête
		bodyBytes, err := io.ReadAll(r.Body)
		if err != nil {
			http.Error(w, "Failed to read request body", http.StatusInternalServerError)
			return
		}
		// Réinitialiser le corps pour l'envoi au proxy
		r.Body = io.NopCloser(bytes.NewReader(bodyBytes))

		// Préparer les données pour la détection
		detectionData := map[string]interface{}{
			"uri":  r.RequestURI,
			"body": string(bodyBytes),
		}
		detectionResponse, err := sendToDetectionService(detectionData)
		if err != nil {
			http.Error(w, "Failed to connect to detection service", http.StatusInternalServerError)
			return
		}

		// Vérifiez la réponse de la détection
		if detectionResponse["authorized"] == "MALICIOUS" {
			http.Error(w, "Request blocked due to malicious content", http.StatusForbidden)
			return
		}

		// Passez la requête au proxy si elle est considérée comme safe
		proxy.ServeHTTP(w, r)
	})
	go func() {
		pubsub := redisClient.Subscribe(ctx, "proxy_updates")
		defer pubsub.Close()

		for msg := range pubsub.Channel() {
			log.Printf("Received new proxy update: %s", msg.Payload)
			currentProxyURL = msg.Payload
		}
	}()
	// Configurer HTTPS avec les certificats
	server := &http.Server{
		Addr:    address,
		Handler: mux,
		TLSConfig: &tls.Config{
			MinVersion: tls.VersionTLS12,
		},
	}

	log.Printf("Starting HTTPS proxy server %s on %s", proxyID, address)
	server.ListenAndServeTLS("server.crt", "server.key") // Spécifier les certificats SSL ici
}

func getNewProxyURL() string {
	// Retourner le proxy actif actuel
	return currentProxyURL
}
