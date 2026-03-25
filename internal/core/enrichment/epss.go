// Package enrichment provides post-scan intelligence enrichment for XPFarm.
// EPSS enricher: fetches exploit probability scores from api.first.org (free, no auth).
package enrichment

import (
	"encoding/json"
	"fmt"
	"net/http"
	"strings"
	"time"

	"gorm.io/gorm"
	"gorm.io/gorm/clause"
	"xpfarm/internal/database"
	"xpfarm/pkg/utils"
)

var epssClient = &http.Client{Timeout: 15 * time.Second}

type epssAPIResponse struct {
	Status     string `json:"status"`
	StatusCode int    `json:"status-code"`
	Data       []struct {
		CVE        string `json:"cve"`
		EPSS       string `json:"epss"`
		Percentile string `json:"percentile"`
		Date       string `json:"date"`
	} `json:"data"`
}

// EnrichCVEsWithEPSS fetches EPSS scores from api.first.org for all CVEs
// belonging to targetID that are missing a percentile. Batches up to 100 CVEs
// per API call to respect FIRST.org guidance.
func EnrichCVEsWithEPSS(db *gorm.DB, targetID uint) {
	var cves []database.CVE
	db.Where("target_id = ? AND cve_id != '' AND epss_percentile = 0", targetID).Find(&cves)
	if len(cves) == 0 {
		return
	}

	// Build batches of up to 100
	const batchSize = 100
	for i := 0; i < len(cves); i += batchSize {
		end := i + batchSize
		if end > len(cves) {
			end = len(cves)
		}
		batch := cves[i:end]
		enrichBatch(db, batch)
	}
}

func enrichBatch(db *gorm.DB, batch []database.CVE) {
	ids := make([]string, len(batch))
	idMap := make(map[string]*database.CVE, len(batch))
	for i := range batch {
		ids[i] = batch[i].CveID
		idMap[batch[i].CveID] = &batch[i]
	}

	url := fmt.Sprintf("https://api.first.org/data/1.0/epss?cve=%s", strings.Join(ids, ","))
	resp, err := epssClient.Get(url)
	if err != nil {
		utils.LogDebug("[EPSS] API request failed: %v", err)
		return
	}
	defer resp.Body.Close()

	var result epssAPIResponse
	if err := json.NewDecoder(resp.Body).Decode(&result); err != nil {
		utils.LogDebug("[EPSS] Failed to decode response: %v", err)
		return
	}

	updated := 0
	for _, d := range result.Data {
		cve, ok := idMap[d.CVE]
		if !ok {
			continue
		}

		var score, percentile float64
		fmt.Sscanf(d.EPSS, "%f", &score)
		fmt.Sscanf(d.Percentile, "%f", &percentile)

		// Compute compound risk score: cvss * epss * kev_multiplier
		risk := computeRiskScore(cve.CvssScore, score, cve.IsKEV || cve.InVulnCheckKEV)

		db.Model(cve).Clauses(clause.OnConflict{DoNothing: true}).Updates(map[string]interface{}{
			"epss_score":      score,
			"epss_percentile": percentile,
			"risk_score":      risk,
		})
		updated++
	}

	if updated > 0 {
		utils.LogSuccess("[EPSS] Enriched %d/%d CVEs with EPSS scores", updated, len(batch))
	}
}

// computeRiskScore produces a compound risk score from CVSS, EPSS, and KEV status.
// CVSS alone is a severity estimate; EPSS adds "is anyone actively exploiting this?";
// KEV confirms active exploitation in the wild — triple weight.
func computeRiskScore(cvss, epss float64, inKev bool) float64 {
	if cvss == 0 && epss == 0 {
		return 0
	}
	// Floor epss at 0.001 so CVSS still contributes even when epss is 0
	e := epss
	if e < 0.001 {
		e = 0.001
	}
	risk := cvss * e
	if inKev {
		risk *= 3.0
	}
	return risk
}
