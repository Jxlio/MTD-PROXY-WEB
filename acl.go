package main

import (
	"net"
	"net/http"
	"os"
	"regexp"
	"strings"

	"gopkg.in/yaml.v2"
)

func getEffectiveClientIP(r *http.Request, overrideHeader string) string {
	if overrideHeader != "" {
		customIP := r.Header.Get(overrideHeader)
		if customIP != "" {
			return strings.TrimSpace(customIP)
		}
	}

	xForwardedFor := r.Header.Get("X-Forwarded-For")
	if xForwardedFor != "" {
		ips := strings.Split(xForwardedFor, ",")
		return strings.TrimSpace(ips[0])
	}

	return strings.Split(r.RemoteAddr, ":")[0]
}

func LoadACLConfig(filepath string) (*ACLConfig, error) {
	data, err := os.ReadFile(filepath)
	if err != nil {
		return nil, err
	}

	var config ACLConfig
	err = yaml.Unmarshal(data, &config)
	if err != nil {
		return nil, err
	}

	return &config, nil
}

func EvaluateACLs(req *http.Request, aclConfig *ACLConfig) (string, error) {
	for _, rule := range aclConfig.Rules {
		switch rule.Condition {
		case "path_beg":
			if strings.HasPrefix(req.URL.Path, rule.Value.(string)) {
				return rule.Action, nil
			}
		case "method":
			if strings.EqualFold(req.Method, rule.Value.(string)) {
				return rule.Action, nil
			}
		case "path_reg":
			matched, err := regexp.MatchString(rule.Value.(string), req.URL.Path)
			if err != nil {
				return "", err
			}
			if matched {
				return rule.Action, nil
			}
		}
	}
	return "", nil
}

func HandleRequestWithACL(r *http.Request, w http.ResponseWriter, aclConfig *ACLConfig) bool {
	for _, rule := range aclConfig.Rules {
		matched := false

		switch rule.Condition {
		case "path_beg":
			matched = strings.HasPrefix(r.URL.Path, rule.Value.(string))
		case "path_end":
			matched = strings.HasSuffix(r.URL.Path, rule.Value.(string))
		case "path_sub":
			matched = strings.Contains(r.URL.Path, rule.Value.(string))
		case "method":
			matched = strings.EqualFold(r.Method, rule.Value.(string))
		case "header":
			if len(rule.Options) > 0 {
				headerValue := r.Header.Get(rule.Options[0])
				matched = strings.EqualFold(strings.TrimSpace(headerValue), strings.TrimSpace(rule.Value.(string)))
			}
		case "query_param":
			queryValues := r.URL.Query()
			matched = queryValues.Get(rule.Value.(string)) != ""
		case "query_param_val":
			if len(rule.Options) > 0 {
				queryValues := r.URL.Query()
				matched = queryValues.Get(rule.Value.(string)) == rule.Options[0]
			}
		case "ip_src":
			overrideHeader := ""
			if len(rule.Options) > 0 {
				overrideHeader = rule.Options[0]
			}
			clientIP := getEffectiveClientIP(r, overrideHeader)
			matched = clientIP == rule.Value.(string)
		case "ip_src_range":
			overrideHeader := ""
			if len(rule.Options) > 0 {
				overrideHeader = rule.Options[0]
			}
			clientIP := getEffectiveClientIP(r, overrideHeader)
			matched = ipInRange(clientIP, rule.Value.(string))
		case "ssl":
			matched = r.TLS != nil
		case "cookie":
			cookie, err := r.Cookie(rule.Value.(string))
			matched = err == nil && cookie != nil
		case "cookie_val":
			if len(rule.Options) > 0 {
				cookie, err := r.Cookie(rule.Value.(string))
				matched = err == nil && cookie != nil && cookie.Value == rule.Options[0]
			}
		case "method_path_beg":
			if valueMap, ok := rule.Value.(map[string]interface{}); ok {
				method, okMethod := valueMap["method"].(string)
				path, okPath := valueMap["path"].(string)
				matched = okMethod && okPath && r.Method == method && strings.HasPrefix(r.URL.Path, path)
			}
		case "always":
			matched = true
		}

		if matched {
			switch rule.Action {
			case "deny":
				http.Error(w, "Access Denied", http.StatusForbidden)
				return true
			case "redirect":
				if len(rule.Options) > 0 {
					redirectURL := rule.Options[0]
					http.Redirect(w, r, redirectURL, http.StatusFound)
					return true
				}
			case "allow":
				logInfo("Allowing request due to rule: %s", rule.Name)
				return false
			}
		}
	}

	logInfo("No ACL rules matched for the request")
	return false
}

func ipInRange(remoteAddr, ruleValue string) bool {
	clientIP := strings.Split(remoteAddr, ":")[0]
	_, ipNet, err := net.ParseCIDR(ruleValue)
	if err != nil {
		return clientIP == ruleValue
	}

	requestIP := net.ParseIP(clientIP)
	if requestIP == nil {
		return false
	}
	return ipNet.Contains(requestIP)
}
