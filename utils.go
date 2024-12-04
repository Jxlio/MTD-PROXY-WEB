package main

import (
	"crypto/tls"
	"io"
	"log"
	"net"
	"net/http"
	"net/http/httputil"
	"os"
	"regexp"

	"gopkg.in/yaml.v2"

	"github.com/go-redis/redis/v8"
)

var (
	redisClient      *redis.Client
	currentProxyURL  string
	headerRules      []HeaderRule
	logFile          *os.File
	requestLogFile   *os.File
	backendURLserver string
)

func configureLogger(verbose bool) {
	var err error
	logFile, err = os.OpenFile("proxy.log", os.O_APPEND|os.O_CREATE|os.O_WRONLY, 0644)
	if err != nil {
		log.Fatalf("Failed to open log file: %v", err)
	}

	if verbose {
		log.SetOutput(io.MultiWriter(os.Stdout, logFile))
	} else {
		log.SetOutput(logFile)
	}

	requestLogFile, err = os.OpenFile("requests.log", os.O_APPEND|os.O_CREATE|os.O_WRONLY, 0644)
	if err != nil {
		log.Fatalf("Failed to open request log file: %v", err)
	}
}

func logInfo(format string, v ...interface{}) {

	log.Printf(ColorBlue+"INFO: "+format+ColorReset, v...)
}

func logError(format string, v ...interface{}) {
	log.Printf(ColorRed+"ERROR: "+format+ColorReset, v...)
}

func logWarning(format string, v ...interface{}) {
	log.Printf(ColorYellow+"WARNING: "+format+ColorReset, v...)
}

func logSuccess(format string, v ...interface{}) {
	log.Printf(ColorGreen+"SUCCESS: "+format+ColorReset, v...)
}

func logRequest(r *http.Request) {
	log.SetOutput(requestLogFile)
	sessionID, _ := r.Context().Value("sessionID").(string)
	if sessionID == "" {
		sessionID = "unknown"
	}
	log.Printf("Request: %s %s from %s; User-Agent: %s; SessionID: %s",
		r.Method, r.URL.String(), r.RemoteAddr, r.UserAgent(), sessionID)

	log.SetOutput(logFile)
}

const (
	ColorReset  = "\033[0m"
	ColorRed    = "\033[31m"
	ColorGreen  = "\033[32m"
	ColorYellow = "\033[33m"
	ColorBlue   = "\033[34m"
)

func init() {
	var err error
	logFile, err = os.OpenFile("proxy.log", os.O_APPEND|os.O_CREATE|os.O_WRONLY, 0644)
	if err != nil {
		log.Fatalf("Failed to open log file: %v", err)
	}
	log.SetOutput(logFile)

	requestLogFile, err = os.OpenFile("requests.log", os.O_APPEND|os.O_CREATE|os.O_WRONLY, 0644)
	if err != nil {
		log.Fatalf("Failed to open request log file: %v", err)
	}
}

func loadHeaderRules(filename string) []HeaderRule {
	data, err := os.ReadFile(filename)
	if err != nil {
		logError("Failed to read header rules file: " + err.Error())
	}

	var config HeaderRulesConfig
	err = yaml.Unmarshal(data, &config)
	if err != nil {
		logError("Failed to parse header rules: " + err.Error())
	}
	logSuccess("Header rules loaded successfully")
	return config.HeaderRules
}

func applyHeaderRules(resp *http.Response) {
	for _, rule := range headerRules {
		switch rule.Action {
		case "add-header":
			resp.Header.Add(rule.Header, rule.Value)
		case "set-header":
			resp.Header.Set(rule.Header, rule.Value)
		case "del-header":
			resp.Header.Del(rule.Header)
		case "replace-header":
			if rule.Regex != "" {
				if value := resp.Header.Get(rule.Header); value != "" {
					re := regexp.MustCompile(rule.Regex)
					newValue := re.ReplaceAllString(value, rule.Replacement)
					resp.Header.Set(rule.Header, newValue)
				}
			}
		}
	}
}

func getServerIPAddress() string {
	addrs, err := net.InterfaceAddrs()
	if err != nil {
		logError("Failed to get network interfaces: " + err.Error())
	}
	var loopbackIP string
	for _, addr := range addrs {
		if ipNet, ok := addr.(*net.IPNet); ok {
			if ipNet.IP.To4() != nil {
				if ipNet.IP.IsLoopback() {
					loopbackIP = ipNet.IP.String()
				} else {
					return ipNet.IP.String()
				}
			}
		}
	}
	if loopbackIP != "" {
		return loopbackIP
	}
	log.Fatalf("No valid IP address found")
	return ""
}

func EnableSkipSecureVerify(proxy *httputil.ReverseProxy) {
	if unsecureCert {
		proxy.Transport = &http.Transport{
			TLSClientConfig: &tls.Config{
				InsecureSkipVerify: true,
			},
		}
	} else {
		proxy.Transport = &http.Transport{
			TLSClientConfig: &tls.Config{
				InsecureSkipVerify: false,
			},
		}
	}
}
