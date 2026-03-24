package graph

import (
	"context"
	"fmt"
	"regexp"
	"strings"

	"xpfarm/internal/database"

	"gorm.io/gorm"
)

// webPorts is the set of TCP port numbers typically associated with HTTP(S).
// When a Port in this set is found, its target's web-detected technologies
// are wired to it via "runs" edges.
var webPorts = map[int]bool{
	80: true, 81: true, 443: true,
	591: true, 593: true,
	3000: true, 4200: true,
	5000: true, 5001: true,
	7000: true, 7001: true,
	8000: true, 8001: true, 8008: true,
	8080: true, 8081: true, 8443: true,
	8888: true, 9000: true, 9090: true,
	9200: true, 9443: true,
}

// reSanitize strips characters that are not URL/ID-safe.
var reSanitize = regexp.MustCompile(`[^a-z0-9]+`)

// techNodeID returns a deterministic, filesystem-safe node ID for a technology name.
func techNodeID(name string) string {
	s := strings.ToLower(strings.TrimSpace(name))
	s = reSanitize.ReplaceAllString(s, "-")
	s = strings.Trim(s, "-")
	if s == "" {
		return ""
	}
	return "tech-" + s
}

// BuildGraph queries all XPFarm data from db and returns a ScanGraph.
// The graph contains six node types:
//
//	asset    — top-level scan scope
//	target   — individual host/domain/URL/CIDR
//	service  — open port + detected service
//	tech     — detected technology (web stack, libraries)
//	vuln     — Nuclei finding or CVE entry
//	exploit  — CVE with a known exploit (KEV + PoC)
//
// Edges:  asset → target (owns)
//
//	target → service (exposes)
//	service → tech   (runs)
//	target  → vuln   (affected-by)
//	vuln    → exploit (exploits)
func BuildGraph(ctx context.Context, db *gorm.DB) (*ScanGraph, error) {
	g := &ScanGraph{
		Nodes: make([]GraphNode, 0, 64),
		Edges: make([]GraphEdge, 0, 128),
	}

	seenTech := make(map[string]struct{})  // dedup tech nodes by ID
	seenEdge := make(map[string]struct{})  // dedup edges by from+kind+to
	seenNode := make(map[string]struct{})  // dedup any node by ID

	addNode := func(n GraphNode) {
		if _, exists := seenNode[n.ID]; exists {
			return
		}
		seenNode[n.ID] = struct{}{}
		g.Nodes = append(g.Nodes, n)
	}

	addEdge := func(from, to, kind string) {
		key := from + "\x00" + kind + "\x00" + to
		if _, exists := seenEdge[key]; exists {
			return
		}
		seenEdge[key] = struct{}{}
		g.Edges = append(g.Edges, GraphEdge{
			ID:   fmt.Sprintf("e-%s-%s-%s", kind, from, to),
			From: from,
			To:   to,
			Kind: kind,
		})
	}

	// ensureTechNode adds a tech node if it hasn't been seen yet and returns
	// its ID. Returns "" if name is blank.
	ensureTechNode := func(name string) string {
		name = strings.TrimSpace(name)
		if name == "" {
			return ""
		}
		id := techNodeID(name)
		if id == "" {
			return ""
		}
		if _, exists := seenTech[id]; !exists {
			seenTech[id] = struct{}{}
			addNode(GraphNode{
				ID:    id,
				Type:  NodeTech,
				Label: name,
				Data:  map[string]any{"technology": name},
			})
		}
		return id
	}

	// ── Step 1: Assets + Targets ───────────────────────────────────────────
	if err := ctx.Err(); err != nil {
		return nil, err
	}
	var assets []database.Asset
	if err := db.Preload("Targets").Find(&assets).Error; err != nil {
		return nil, fmt.Errorf("graph: query assets: %w", err)
	}

	// Build lookup maps keyed by Target.ID for use in later steps.
	targetNodeID := make(map[uint]string)    // target.ID → node ID
	targetAssetNode := make(map[uint]string) // target.ID → parent asset node ID

	for _, a := range assets {
		assetNID := fmt.Sprintf("asset-%d", a.ID)
		addNode(GraphNode{
			ID:    assetNID,
			Type:  NodeAsset,
			Label: a.Name,
			Data: map[string]any{
				"id":            a.ID,
				"advanced_mode": a.AdvancedMode,
				"target_count":  len(a.Targets),
			},
		})

		for _, t := range a.Targets {
			tNID := fmt.Sprintf("target-%d", t.ID)
			targetNodeID[t.ID] = tNID
			targetAssetNode[t.ID] = assetNID

			addNode(GraphNode{
				ID:    tNID,
				Type:  NodeTarget,
				Label: t.Value,
				Data: map[string]any{
					"id":           t.ID,
					"type":         t.Type,
					"is_alive":     t.IsAlive,
					"is_cloudflare": t.IsCloudflare,
					"is_localhost": t.IsLocalhost,
					"status":       t.Status,
				},
			})
			addEdge(assetNID, tNID, "owns")
		}
	}

	// ── Step 2: Ports → Service nodes ─────────────────────────────────────
	if err := ctx.Err(); err != nil {
		return nil, err
	}
	var ports []database.Port
	if err := db.Find(&ports).Error; err != nil {
		return nil, fmt.Errorf("graph: query ports: %w", err)
	}

	// targetHTTPServiceNode maps target.ID → web-port service node IDs.
	// Used when wiring web tech to service nodes in Step 3.
	targetHTTPServiceNode := make(map[uint][]string)

	for _, p := range ports {
		tNID, ok := targetNodeID[p.TargetID]
		if !ok {
			continue // orphaned port — target was deleted
		}
		svcNID := fmt.Sprintf("service-%d", p.ID)

		label := fmt.Sprintf("%d/%s", p.Port, p.Protocol)
		if p.Service != "" {
			label = fmt.Sprintf("%d/%s (%s)", p.Port, p.Protocol, p.Service)
		}

		addNode(GraphNode{
			ID:    svcNID,
			Type:  NodeService,
			Label: label,
			Data: map[string]any{
				"id":       p.ID,
				"port":     p.Port,
				"protocol": p.Protocol,
				"service":  p.Service,
				"product":  p.Product,
				"version":  p.Version,
			},
		})
		addEdge(tNID, svcNID, "exposes")

		// If the port has a detected product, create a Tech node for it.
		if p.Product != "" {
			techName := p.Product
			if p.Version != "" {
				techName = p.Product + " " + p.Version
			}
			if tid := ensureTechNode(techName); tid != "" {
				addEdge(svcNID, tid, "runs")
			}
		}

		// Track web-capable service nodes for web tech wiring in Step 3.
		if webPorts[p.Port] {
			targetHTTPServiceNode[p.TargetID] = append(targetHTTPServiceNode[p.TargetID], svcNID)
		}
	}

	// ── Step 3: WebAssets → Tech nodes ────────────────────────────────────
	if err := ctx.Err(); err != nil {
		return nil, err
	}
	var webAssets []database.WebAsset
	if err := db.Find(&webAssets).Error; err != nil {
		return nil, fmt.Errorf("graph: query web assets: %w", err)
	}

	for _, wa := range webAssets {
		if wa.TechStack == "" {
			continue
		}
		tNID, ok := targetNodeID[wa.TargetID]
		if !ok {
			continue
		}

		httpSvcs := targetHTTPServiceNode[wa.TargetID]

		// Parse comma-separated tech stack.
		for _, raw := range strings.Split(wa.TechStack, ",") {
			name := strings.TrimSpace(raw)
			if name == "" {
				continue
			}
			tid := ensureTechNode(name)
			if tid == "" {
				continue
			}

			// Prefer Service → Tech edges; fall back to Target → Tech.
			if len(httpSvcs) > 0 {
				for _, svcNID := range httpSvcs {
					addEdge(svcNID, tid, "runs")
				}
			} else {
				addEdge(tNID, tid, "runs")
			}
		}
	}

	// ── Step 4: Vulnerabilities → Vuln nodes ──────────────────────────────
	if err := ctx.Err(); err != nil {
		return nil, err
	}
	var vulns []database.Vulnerability
	if err := db.Find(&vulns).Error; err != nil {
		return nil, fmt.Errorf("graph: query vulnerabilities: %w", err)
	}

	for _, v := range vulns {
		tNID, ok := targetNodeID[v.TargetID]
		if !ok {
			continue
		}
		vNID := fmt.Sprintf("vuln-%d", v.ID)
		addNode(GraphNode{
			ID:    vNID,
			Type:  NodeVuln,
			Label: v.Name,
			Data: map[string]any{
				"id":          v.ID,
				"severity":    v.Severity,
				"template_id": v.TemplateID,
				"matcher":     v.MatcherName,
				"description": v.Description,
				"extracted":   v.Extracted,
				"source":      "nuclei",
			},
		})
		addEdge(tNID, vNID, "affected-by")
	}

	// ── Step 5: CVEs → Vuln nodes (+ Exploit nodes for KEV + PoC) ─────────
	if err := ctx.Err(); err != nil {
		return nil, err
	}
	var cves []database.CVE
	if err := db.Find(&cves).Error; err != nil {
		return nil, fmt.Errorf("graph: query cves: %w", err)
	}

	for _, c := range cves {
		tNID, ok := targetNodeID[c.TargetID]
		if !ok {
			continue
		}
		cveNID := fmt.Sprintf("cve-%d", c.ID)
		addNode(GraphNode{
			ID:    cveNID,
			Type:  NodeVuln,
			Label: c.CveID,
			Data: map[string]any{
				"id":           c.ID,
				"cve_id":       c.CveID,
				"product":      c.Product,
				"severity":     c.Severity,
				"cvss_score":   c.CvssScore,
				"epss_score":   c.EpssScore,
				"is_kev":       c.IsKEV,
				"has_poc":      c.HasPOC,
				"has_template": c.HasTemplate,
				"source":       "cvemap",
			},
		})
		addEdge(tNID, cveNID, "affected-by")

		// A CVE with a known exploit in CISA KEV AND an available PoC is
		// actionable — surface it as an Exploit node.
		if c.IsKEV && c.HasPOC {
			exploitNID := fmt.Sprintf("exploit-cve-%d", c.ID)
			addNode(GraphNode{
				ID:    exploitNID,
				Type:  NodeExploit,
				Label: "Exploit: " + c.CveID,
				Data: map[string]any{
					"cve_id":       c.CveID,
					"product":      c.Product,
					"cvss_score":   c.CvssScore,
					"epss_score":   c.EpssScore,
					"has_template": c.HasTemplate,
					"source":       "kev+poc",
				},
			})
			addEdge(cveNID, exploitNID, "exploits")
		}
	}

	return g, nil
}
