// MCP (Model Context Protocol) server for XPFarm.
// Exposes XPFarm tools to any MCP-compatible AI client (Claude Desktop, Cursor, etc.).
// Runs on port :8889 alongside the main web UI on :8888.
// Start by calling StartMCPServer(db) in a goroutine from main.go.
package mcp

import (
	"context"
	"encoding/json"
	"fmt"
	"strings"

	"github.com/mark3labs/mcp-go/mcp"
	"github.com/mark3labs/mcp-go/server"
	"gorm.io/gorm"
	"xpfarm/internal/core"
	"xpfarm/internal/database"
	"xpfarm/pkg/utils"
)

// StartMCPServer starts the MCP SSE server on :8889.
// Tools exposed:
//   - start_scan       — kick off a scan for a target
//   - get_findings     — query vulnerability/CVE findings
//   - list_assets      — list all assets
//   - get_target_info  — ports, web assets, CVEs for a target
//   - search           — global text search across all data
func StartMCPServer(db *gorm.DB) {
	s := server.NewMCPServer(
		"XPFarm",
		"1.0.0",
		server.WithToolCapabilities(true),
	)

	// --- Tool: start_scan ---
	s.AddTool(mcp.NewTool("start_scan",
		mcp.WithDescription("Start a vulnerability scan for a target (domain, IP, or CIDR). Returns immediately; scan runs in background."),
		mcp.WithString("target", mcp.Required(), mcp.Description("Target to scan (e.g. example.com, 192.168.1.0/24)")),
		mcp.WithString("asset_name", mcp.Description("Asset group name (defaults to 'Default')")),
	), func(ctx context.Context, req mcp.CallToolRequest) (*mcp.CallToolResult, error) {
		target := req.GetString("target", "")
		assetName := req.GetString("asset_name", "Default")
		if target == "" {
			return mcp.NewToolResultError("target is required"), nil
		}
		mgr := core.GetManager()
		mgr.StartScan(target, assetName)
		return mcp.NewToolResultText(fmt.Sprintf("Scan started for %s (asset: %s). Monitor progress at http://localhost:8888", target, assetName)), nil
	})

	// --- Tool: get_findings ---
	s.AddTool(mcp.NewTool("get_findings",
		mcp.WithDescription("Get vulnerability and CVE findings. Optionally filter by severity or asset name."),
		mcp.WithString("severity", mcp.Description("Filter by severity: critical, high, medium, low, info")),
		mcp.WithString("asset_name", mcp.Description("Filter by asset name")),
		mcp.WithNumber("limit", mcp.Description("Max results to return (default 50)")),
	), func(ctx context.Context, req mcp.CallToolRequest) (*mcp.CallToolResult, error) {
		severity := req.GetString("severity", "")
		assetName := req.GetString("asset_name", "")
		limit := req.GetInt("limit", 50)

		type FindingRow struct {
			TargetValue string  `json:"target"`
			AssetName   string  `json:"asset"`
			Name        string  `json:"name"`
			Severity    string  `json:"severity"`
			TemplateID  string  `json:"template_id,omitempty"`
			CveID       string  `json:"cve_id,omitempty"`
			CvssScore   float64 `json:"cvss,omitempty"`
			EpssScore   float64 `json:"epss,omitempty"`
			IsKEV       bool    `json:"kev,omitempty"`
			FpStatus    string  `json:"triage_status,omitempty"`
		}

		var results []FindingRow

		// Vulnerabilities
		var vulns []database.Vulnerability
		vq := db.Limit(limit).Where("fp_status != 'false_positive'")
		if severity != "" {
			vq = vq.Where("LOWER(severity) = ?", strings.ToLower(severity))
		}
		vq.Find(&vulns)
		for _, v := range vulns {
			var t database.Target
			db.Select("value, asset_id").First(&t, v.TargetID)
			var asset database.Asset
			db.Select("name").First(&asset, t.AssetID)
			if assetName != "" && !strings.EqualFold(asset.Name, assetName) {
				continue
			}
			results = append(results, FindingRow{
				TargetValue: t.Value,
				AssetName:   asset.Name,
				Name:        v.Name,
				Severity:    v.Severity,
				TemplateID:  v.TemplateID,
				FpStatus:    v.FpStatus,
			})
		}

		// CVEs
		var cves []database.CVE
		cq := db.Limit(limit)
		if severity != "" {
			cq = cq.Where("LOWER(severity) = ?", strings.ToLower(severity))
		}
		cq.Find(&cves)
		for _, c := range cves {
			var t database.Target
			db.Select("value, asset_id").First(&t, c.TargetID)
			var asset database.Asset
			db.Select("name").First(&asset, t.AssetID)
			if assetName != "" && !strings.EqualFold(asset.Name, assetName) {
				continue
			}
			results = append(results, FindingRow{
				TargetValue: t.Value,
				AssetName:   asset.Name,
				Name:        c.CveID,
				Severity:    c.Severity,
				CveID:       c.CveID,
				CvssScore:   c.CvssScore,
				EpssScore:   c.EpssScore,
				IsKEV:       c.IsKEV || c.InVulnCheckKEV,
			})
		}

		out, _ := json.MarshalIndent(results, "", "  ")
		return mcp.NewToolResultText(string(out)), nil
	})

	// --- Tool: list_assets ---
	s.AddTool(mcp.NewTool("list_assets",
		mcp.WithDescription("List all assets (scope groups) in XPFarm with their target counts."),
	), func(ctx context.Context, req mcp.CallToolRequest) (*mcp.CallToolResult, error) {
		type AssetRow struct {
			ID          uint   `json:"id"`
			Name        string `json:"name"`
			TargetCount int64  `json:"target_count"`
		}
		var assets []database.Asset
		db.Find(&assets)
		rows := make([]AssetRow, 0, len(assets))
		for _, a := range assets {
			var count int64
			db.Model(&database.Target{}).Where("asset_id = ?", a.ID).Count(&count)
			rows = append(rows, AssetRow{ID: a.ID, Name: a.Name, TargetCount: count})
		}
		out, _ := json.MarshalIndent(rows, "", "  ")
		return mcp.NewToolResultText(string(out)), nil
	})

	// --- Tool: get_target_info ---
	s.AddTool(mcp.NewTool("get_target_info",
		mcp.WithDescription("Get detailed scan results for a specific target: open ports, web assets, CVEs, vulnerabilities."),
		mcp.WithString("target", mcp.Required(), mcp.Description("Target value (domain or IP)")),
	), func(ctx context.Context, req mcp.CallToolRequest) (*mcp.CallToolResult, error) {
		targetVal := req.GetString("target", "")
		if targetVal == "" {
			return mcp.NewToolResultError("target is required"), nil
		}
		var t database.Target
		if err := db.Where("value LIKE ?", "%"+targetVal+"%").First(&t).Error; err != nil {
			return mcp.NewToolResultText(fmt.Sprintf("No target found matching: %s", targetVal)), nil
		}

		var ports []database.Port
		db.Where("target_id = ?", t.ID).Find(&ports)
		var webAssets []database.WebAsset
		db.Where("target_id = ?", t.ID).Find(&webAssets)
		var cves []database.CVE
		db.Where("target_id = ?", t.ID).Find(&cves)
		var vulns []database.Vulnerability
		db.Where("target_id = ? AND fp_status != 'false_positive'", t.ID).Find(&vulns)

		result := map[string]interface{}{
			"target":     t.Value,
			"type":       t.Type,
			"score":      t.Score,
			"is_alive":   t.IsAlive,
			"ports":      ports,
			"web_assets": webAssets,
			"cves":       cves,
			"vulns":      vulns,
		}
		out, _ := json.MarshalIndent(result, "", "  ")
		return mcp.NewToolResultText(string(out)), nil
	})

	// --- Tool: search ---
	s.AddTool(mcp.NewTool("search",
		mcp.WithDescription("Full-text search across all XPFarm data: targets, vulnerabilities, CVEs, ports, web assets."),
		mcp.WithString("query", mcp.Required(), mcp.Description("Search query string")),
	), func(ctx context.Context, req mcp.CallToolRequest) (*mcp.CallToolResult, error) {
		query := req.GetString("query", "")
		if query == "" {
			return mcp.NewToolResultError("query is required"), nil
		}

		type SearchResult struct {
			Type  string `json:"type"`
			Value string `json:"value"`
			Extra string `json:"extra,omitempty"`
		}
		var results []SearchResult
		like := "%" + query + "%"

		var targets []database.Target
		db.Where("value LIKE ?", like).Limit(10).Find(&targets)
		for _, t := range targets {
			results = append(results, SearchResult{Type: "target", Value: t.Value, Extra: t.Type})
		}

		var vulns []database.Vulnerability
		db.Where("name LIKE ? OR template_id LIKE ?", like, like).Limit(10).Find(&vulns)
		for _, v := range vulns {
			results = append(results, SearchResult{Type: "vulnerability", Value: v.Name, Extra: v.Severity})
		}

		var cves []database.CVE
		db.Where("cve_id LIKE ? OR product LIKE ?", like, like).Limit(10).Find(&cves)
		for _, c := range cves {
			results = append(results, SearchResult{Type: "cve", Value: c.CveID, Extra: c.Severity})
		}

		var ports []database.Port
		db.Where("service LIKE ? OR product LIKE ?", like, like).Limit(10).Find(&ports)
		for _, p := range ports {
			results = append(results, SearchResult{Type: "port", Value: fmt.Sprintf("%d/%s", p.Port, p.Protocol), Extra: p.Service})
		}

		if len(results) == 0 {
			return mcp.NewToolResultText("No results found for: " + query), nil
		}
		out, _ := json.MarshalIndent(results, "", "  ")
		return mcp.NewToolResultText(string(out)), nil
	})

	utils.LogInfo("[MCP] Starting MCP server on :8889")
	sseServer := server.NewSSEServer(s, server.WithBaseURL("http://localhost:8889"))
	if err := sseServer.Start(":8889"); err != nil {
		utils.LogError("[MCP] Server error: %v", err)
	}
}
