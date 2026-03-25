// GreyNoise enricher: classifies IPs as scanner/benign/malicious before active
// scanning. IPs tagged riot=true (legitimate internet services) or classified as
// "benign" (known scanners, research networks) are de-prioritised. This prevents
// wasting scan time on noise and avoids scanning honeypots.
//
// API: https://api.greynoise.io/v3/community/{ip}  (free tier, key required)
// Rate limit: generous for community tier; 24-hour in-memory cache prevents abuse.
package enrichment

import (
	"encoding/json"
	"fmt"
	"net/http"
	"os"
	"sync"
	"time"

	"xpfarm/pkg/utils"
)

// GreyNoiseResult holds the classification result for a single IP.
type GreyNoiseResult struct {
	IP             string `json:"ip"`
	Noise          bool   `json:"noise"`   // Known internet scanner
	Riot           bool   `json:"riot"`    // Known legitimate internet service (AWS health, etc.)
	Classification string `json:"classification"` // "benign", "malicious", "unknown"
	Name           string `json:"name"`    // Org name if riot=true
	Message        string `json:"message"` // Error message from API
}

// ShouldSkip returns true if the IP should be excluded from active scanning.
// We skip RIOT addresses (legit services that flood scan results) and
// addresses we know nothing about are kept (unknown = scan normally).
func (r *GreyNoiseResult) ShouldSkip() bool {
	return r.Riot
}

// IsSuspicious returns true if GreyNoise classifies the IP as malicious.
func (r *GreyNoiseResult) IsSuspicious() bool {
	return r.Classification == "malicious"
}

var (
	gnCache   = make(map[string]*gnCacheEntry)
	gnCacheMu sync.RWMutex
	gnClient  = &http.Client{Timeout: 10 * time.Second}
)

type gnCacheEntry struct {
	result    *GreyNoiseResult
	fetchedAt time.Time
}

const gnCacheTTL = 24 * time.Hour

// CheckGreyNoise queries the GreyNoise community API for a single IP.
// Returns nil if no API key is configured (graceful degradation).
// Results are cached for 24 hours.
func CheckGreyNoise(ip string) *GreyNoiseResult {
	apiKey := os.Getenv("GREYNOISE_API_KEY")
	if apiKey == "" {
		return nil
	}

	// Check cache
	gnCacheMu.RLock()
	if entry, ok := gnCache[ip]; ok && time.Since(entry.fetchedAt) < gnCacheTTL {
		gnCacheMu.RUnlock()
		return entry.result
	}
	gnCacheMu.RUnlock()

	url := fmt.Sprintf("https://api.greynoise.io/v3/community/%s", ip)
	req, err := http.NewRequest("GET", url, nil)
	if err != nil {
		utils.LogDebug("[GreyNoise] Failed to build request for %s: %v", ip, err)
		return nil
	}
	req.Header.Set("key", apiKey)
	req.Header.Set("Accept", "application/json")

	resp, err := gnClient.Do(req)
	if err != nil {
		utils.LogDebug("[GreyNoise] Request failed for %s: %v", ip, err)
		return nil
	}
	defer resp.Body.Close()

	var result GreyNoiseResult
	if err := json.NewDecoder(resp.Body).Decode(&result); err != nil {
		utils.LogDebug("[GreyNoise] Failed to decode response for %s: %v", ip, err)
		return nil
	}
	result.IP = ip

	gnCacheMu.Lock()
	gnCache[ip] = &gnCacheEntry{result: &result, fetchedAt: time.Now()}
	gnCacheMu.Unlock()

	if result.Riot {
		utils.LogDebug("[GreyNoise] %s is RIOT (%s) — will skip active scan", ip, result.Name)
	} else if result.Classification == "malicious" {
		utils.LogDebug("[GreyNoise] %s is classified MALICIOUS", ip)
	}

	return &result
}
