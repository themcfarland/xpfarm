// Package graph defines the XPFarm scan graph model.
// A ScanGraph represents assets, targets, services, technologies,
// vulnerabilities, and exploits as a unified directed graph, enabling
// path-analysis queries like "which services are running a tech with a
// known-exploited CVE?".
package graph

import "encoding/json"

// NodeType classifies a vertex by its security domain role.
type NodeType string

const (
	NodeAsset   NodeType = "asset"
	NodeTarget  NodeType = "target"
	NodeService NodeType = "service"
	NodeTech    NodeType = "tech"
	NodeVuln    NodeType = "vuln"
	NodeExploit NodeType = "exploit"
)

// GraphNode is a vertex in the scan graph.
type GraphNode struct {
	ID    string         `json:"id"`
	Type  NodeType       `json:"type"`
	Label string         `json:"label"`
	Data  map[string]any `json:"data"`
}

// GraphEdge is a directed relationship between two nodes.
// Kind is one of: "owns" | "exposes" | "runs" | "affected-by" | "exploits"
type GraphEdge struct {
	ID   string `json:"id"`
	From string `json:"from"`
	To   string `json:"to"`
	Kind string `json:"kind"`
}

// ScanGraph is the complete graph of all discovered entities and their
// relationships in one XPFarm workspace.
type ScanGraph struct {
	Nodes []GraphNode `json:"nodes"`
	Edges []GraphEdge `json:"edges"`
}

// NodeCount returns the number of nodes of the given type.
func (g *ScanGraph) NodeCount(t NodeType) int {
	n := 0
	for _, node := range g.Nodes {
		if node.Type == t {
			n++
		}
	}
	return n
}

// Stats returns a summary of node counts by type.
func (g *ScanGraph) Stats() map[string]int {
	s := map[string]int{
		"total_nodes": len(g.Nodes),
		"total_edges": len(g.Edges),
	}
	for _, t := range []NodeType{NodeAsset, NodeTarget, NodeService, NodeTech, NodeVuln, NodeExploit} {
		s[string(t)+"s"] = g.NodeCount(t)
	}
	return s
}

// ToJSON serializes the graph to compact JSON.
func (g *ScanGraph) ToJSON() ([]byte, error) {
	return json.Marshal(g)
}
