package main

import (
	"net"
	"net/http"
	"os"
	"regexp"
	"strings"

	"gopkg.in/yaml.v2"
)

// getEffectiveClientIP returns the effective client IP address based on the request headers.
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

// LoadACLConfig loads the ACL configuration from the given file.
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

// EvaluateACLs evaluates the ACL rules based on the request and returns the action to be taken.
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

// HandleRequestWithACL handles the incoming request based on the ACL configuration.
func HandleRequestWithACL(r *http.Request, w http.ResponseWriter, aclConfig *ACLConfig) bool {
	rules := aclConfig.GetRules()
	for _, rule := range rules {
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

// ipInRange checks if the given IP address is in the given CIDR range.
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

// AddRule adds a rule to the ACL configuration.
func (config *ACLConfig) AddRule(rule ACLRule) {
	config.mu.Lock()
	defer config.mu.Unlock()
	config.Rules = append(config.Rules, rule)
}

// RemoveRule removes a rule from the ACL configuration.
func (config *ACLConfig) RemoveRule(name string) {
	config.mu.Lock()
	defer config.mu.Unlock()
	for i, rule := range config.Rules {
		if rule.Name == name {
			config.Rules = append(config.Rules[:i], config.Rules[i+1:]...)
			break
		}
	}
}

// UpdateRule updates an existing rule in the ACL configuration.
func (config *ACLConfig) UpdateRule(updatedRule ACLRule) {
	config.mu.Lock()
	defer config.mu.Unlock()
	for i, rule := range config.Rules {
		if rule.Name == updatedRule.Name {
			config.Rules[i] = updatedRule
			break
		}
	}
}

// GetRules returns the list of rules in the ACL configuration.
func (config *ACLConfig) GetRules() []ACLRule {
	config.mu.RLock()
	defer config.mu.RUnlock()
	return config.Rules
}

// ReloadACL compile rules and ensure that the allow all rule is the last rule in the ACL configuration.
func ReloadACL() {
	aclMutex.Lock()
	defer aclMutex.Unlock()

	aclConfig.EnsureAllowAllLast()
	logInfo("ACL configuration reloaded.")
}

// AddRuleWithPriority add a rule to the ACL configuration at the given priority.
func (config *ACLConfig) AddRuleWithPriority(rule ACLRule, priority int) {
	config.mu.Lock()
	defer config.mu.Unlock()

	if priority < 0 || priority >= len(config.Rules) {
		config.Rules = append(config.Rules, rule)
	} else {
		config.Rules = append(config.Rules[:priority+1], config.Rules[priority:]...)
		config.Rules[priority] = rule
	}
}

// EnsureAllowAllLast ensure that the allow all rule is the last rule in the ACL configuration.
func (config *ACLConfig) EnsureAllowAllLast() {
	config.mu.Lock()
	defer config.mu.Unlock()

	var allowAllRule *ACLRule
	var otherRules []ACLRule

	for _, rule := range config.Rules {
		if rule.Condition == "always" && rule.Action == "allow" {
			allowAllRule = &rule
		} else {
			otherRules = append(otherRules, rule)
		}
	}

	if allowAllRule != nil {
		config.Rules = append(otherRules, *allowAllRule)
	} else {
		config.Rules = otherRules
	}
}
