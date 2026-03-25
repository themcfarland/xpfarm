// VulnCheck KEV enricher: tags CVEs as InVulnCheckKEV using the VulnCheck
// community API. VulnCheck KEV contains ~142% more entries than the CISA KEV
// list, including pre-KEV entries before they reach CISA.
//
// API: https://api.vulncheck.com/v3/index/vulncheck-kev
// Auth: Bearer token via VULNCHECK_API_KEY setting (community tier is free).
package enrichment

import (
	"encoding/json"
	"net/http"
	"os"
	"strings"
	"sync"
	"time"

	"gorm.io/gorm"
	"xpfarm/internal/database"
	"xpfarm/pkg/utils"
)

var (
	vulnCheckKEVCache     map[string]bool
	vulnCheckKEVCacheTime time.Time
	vulnCheckMu           sync.RWMutex
	vcClient              = &http.Client{Timeout: 20 * time.Second}
)

const vulnCheckKEVURL = "https://api.vulncheck.com/v3/index/vulncheck-kev"
const vulnCheckCacheTTL = 24 * time.Hour

type vulnCheckKEVResponse struct {
	Data []struct {
		CVE []string `json:"cve"`
	} `json:"data"`
}

// loadVulnCheckKEV downloads the full VulnCheck KEV index and caches it.
// Returns nil if the API key is not configured (graceful degradation).
func loadVulnCheckKEV() map[string]bool {
	vulnCheckMu.RLock()
	if vulnCheckKEVCache != nil && time.Since(vulnCheckKEVCacheTime) < vulnCheckCacheTTL {
		defer vulnCheckMu.RUnlock()
		return vulnCheckKEVCache
	}
	vulnCheckMu.RUnlock()

	apiKey := os.Getenv("VULNCHECK_API_KEY")
	if apiKey == "" {
		return nil
	}

	req, err := http.NewRequest("GET", vulnCheckKEVURL+"?limit=2000", nil)
	if err != nil {
		utils.LogDebug("[VulnCheck] Failed to build request: %v", err)
		return nil
	}
	req.Header.Set("Authorization", "Bearer "+apiKey)
	req.Header.Set("Accept", "application/json")

	resp, err := vcClient.Do(req)
	if err != nil {
		utils.LogDebug("[VulnCheck] KEV API request failed: %v", err)
		return nil
	}
	defer resp.Body.Close()

	if resp.StatusCode != 200 {
		utils.LogDebug("[VulnCheck] KEV API returned status %d", resp.StatusCode)
		return nil
	}

	var result vulnCheckKEVResponse
	if err := json.NewDecoder(resp.Body).Decode(&result); err != nil {
		utils.LogDebug("[VulnCheck] Failed to decode KEV response: %v", err)
		return nil
	}

	cache := make(map[string]bool)
	for _, entry := range result.Data {
		for _, cveID := range entry.CVE {
			cache[strings.ToUpper(cveID)] = true
		}
	}

	vulnCheckMu.Lock()
	vulnCheckKEVCache = cache
	vulnCheckKEVCacheTime = time.Now()
	vulnCheckMu.Unlock()

	utils.LogSuccess("[VulnCheck] Loaded %d CVEs from VulnCheck KEV index", len(cache))
	return cache
}

// EnrichCVEsWithVulnCheckKEV tags CVEs for targetID that appear in the
// VulnCheck KEV list. Silently skips if no API key is configured.
func EnrichCVEsWithVulnCheckKEV(db *gorm.DB, targetID uint) {
	kev := loadVulnCheckKEV()
	if kev == nil {
		return
	}

	var cves []database.CVE
	db.Where("target_id = ? AND cve_id != ''", targetID).Find(&cves)

	updated := 0
	for i := range cves {
		inKev := kev[strings.ToUpper(cves[i].CveID)]
		if inKev == cves[i].InVulnCheckKEV {
			continue
		}
		// Recompute risk score with updated KEV status
		risk := computeRiskScore(cves[i].CvssScore, cves[i].EpssScore, inKev || cves[i].IsKEV)
		db.Model(&cves[i]).Updates(map[string]interface{}{
			"in_vulncheck_kev": inKev,
			"risk_score":       risk,
		})
		updated++
	}

	if updated > 0 {
		utils.LogSuccess("[VulnCheck] Tagged %d CVEs as VulnCheck KEV for target %d", updated, targetID)
	}
}
