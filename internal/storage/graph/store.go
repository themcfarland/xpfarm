// Package graphstore persists and retrieves ScanGraph snapshots in SQLite.
// Snapshots capture the full graph at a point in time. The latest snapshot
// is used by the query helpers (GetNodeByID, GetEdgesFrom, GetEdgesTo) to
// answer per-node queries without a full graph rebuild.
package graphstore

import (
	"encoding/json"
	"fmt"
	"time"

	"xpfarm/internal/graph"

	"gorm.io/gorm"
)

// GraphSnapshotRecord persists a full ScanGraph as two JSON columns.
type GraphSnapshotRecord struct {
	ID        uint      `gorm:"primaryKey;autoIncrement"`
	NodesJSON string    `gorm:"type:text;not null"`
	EdgesJSON string    `gorm:"type:text;not null"`
	NodeCount int
	EdgeCount int
	BuiltAt   time.Time `gorm:"index"`
}

func (GraphSnapshotRecord) TableName() string { return "graph_snapshots" }

// Migrate creates or updates the graph_snapshots table.
func Migrate(db *gorm.DB) error {
	return db.AutoMigrate(&GraphSnapshotRecord{})
}

// ---------------------------------------------------------------------------

// SaveGraph persists a ScanGraph snapshot to the database.
// Older snapshots are NOT deleted — callers can prune via PruneSnapshots.
func SaveGraph(db *gorm.DB, g *graph.ScanGraph) error {
	nodesJSON, err := json.Marshal(g.Nodes)
	if err != nil {
		return fmt.Errorf("graphstore: encode nodes: %w", err)
	}
	edgesJSON, err := json.Marshal(g.Edges)
	if err != nil {
		return fmt.Errorf("graphstore: encode edges: %w", err)
	}
	rec := GraphSnapshotRecord{
		NodesJSON: string(nodesJSON),
		EdgesJSON: string(edgesJSON),
		NodeCount: len(g.Nodes),
		EdgeCount: len(g.Edges),
		BuiltAt:   time.Now().UTC(),
	}
	return db.Create(&rec).Error
}

// LoadLatestGraph returns the most recently saved ScanGraph snapshot.
// Returns (nil, nil) if no snapshot exists yet.
func LoadLatestGraph(db *gorm.DB) (*graph.ScanGraph, error) {
	var rec GraphSnapshotRecord
	if err := db.Order("built_at desc").First(&rec).Error; err != nil {
		if isNotFound(err) {
			return nil, nil
		}
		return nil, fmt.Errorf("graphstore: load latest: %w", err)
	}
	return decodeSnapshot(rec)
}

// GetNodeByID loads the latest snapshot and returns the node with the given ID.
// Returns (nil, nil) if the node is not found.
func GetNodeByID(db *gorm.DB, id string) (*graph.GraphNode, error) {
	g, err := LoadLatestGraph(db)
	if err != nil {
		return nil, err
	}
	if g == nil {
		return nil, nil
	}
	for _, n := range g.Nodes {
		if n.ID == id {
			cp := n
			return &cp, nil
		}
	}
	return nil, nil
}

// GetEdgesFrom returns all edges originating from nodeID in the latest snapshot.
func GetEdgesFrom(db *gorm.DB, nodeID string) ([]graph.GraphEdge, error) {
	g, err := LoadLatestGraph(db)
	if err != nil {
		return nil, err
	}
	if g == nil {
		return nil, nil
	}
	var out []graph.GraphEdge
	for _, e := range g.Edges {
		if e.From == nodeID {
			out = append(out, e)
		}
	}
	return out, nil
}

// GetEdgesTo returns all edges pointing to nodeID in the latest snapshot.
func GetEdgesTo(db *gorm.DB, nodeID string) ([]graph.GraphEdge, error) {
	g, err := LoadLatestGraph(db)
	if err != nil {
		return nil, err
	}
	if g == nil {
		return nil, nil
	}
	var out []graph.GraphEdge
	for _, e := range g.Edges {
		if e.To == nodeID {
			out = append(out, e)
		}
	}
	return out, nil
}

// PruneSnapshots deletes all but the most recent `keep` snapshots.
func PruneSnapshots(db *gorm.DB, keep int) error {
	if keep < 1 {
		keep = 1
	}
	// Find the cut-off ID
	var records []GraphSnapshotRecord
	if err := db.Select("id").Order("built_at desc").Limit(keep).Find(&records).Error; err != nil {
		return fmt.Errorf("graphstore: prune query: %w", err)
	}
	if len(records) < keep {
		return nil // fewer than keep exist, nothing to prune
	}
	keepIDs := make([]uint, len(records))
	for i, r := range records {
		keepIDs[i] = r.ID
	}
	return db.Where("id NOT IN ?", keepIDs).Delete(&GraphSnapshotRecord{}).Error
}

// ---------------------------------------------------------------------------
// Helpers
// ---------------------------------------------------------------------------

func decodeSnapshot(rec GraphSnapshotRecord) (*graph.ScanGraph, error) {
	var nodes []graph.GraphNode
	var edges []graph.GraphEdge
	if err := json.Unmarshal([]byte(rec.NodesJSON), &nodes); err != nil {
		return nil, fmt.Errorf("graphstore: decode nodes: %w", err)
	}
	if err := json.Unmarshal([]byte(rec.EdgesJSON), &edges); err != nil {
		return nil, fmt.Errorf("graphstore: decode edges: %w", err)
	}
	if nodes == nil {
		nodes = []graph.GraphNode{}
	}
	if edges == nil {
		edges = []graph.GraphEdge{}
	}
	return &graph.ScanGraph{Nodes: nodes, Edges: edges}, nil
}

func isNotFound(err error) bool {
	return err != nil && err.Error() == "record not found"
}
