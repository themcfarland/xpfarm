package scanhistory

import (
	"encoding/json"
	"time"

	"gorm.io/gorm"
)

// SnapshotFinding is a minimal finding record stored inside a scan snapshot.
type SnapshotFinding struct {
	TargetValue string `json:"target"`
	Name        string `json:"name"`
	Severity    string `json:"severity"`
	TemplateID  string `json:"template_id,omitempty"`
	CveID       string `json:"cve_id,omitempty"`
}

// ScanSnapshot captures the state of an asset's findings at a point in time.
type ScanSnapshot struct {
	ID          uint           `gorm:"primaryKey;autoIncrement" json:"id"`
	AssetID     uint           `gorm:"not null;index" json:"asset_id"`
	AssetName   string         `json:"asset_name"`
	ScannedAt   time.Time      `gorm:"index" json:"scanned_at"`
	TargetCount int            `json:"target_count"`
	PortCount   int            `json:"port_count"`
	VulnCount   int            `json:"vuln_count"`
	FindingsJSON string        `gorm:"type:text" json:"-"`
	DeletedAt   gorm.DeletedAt `gorm:"index" json:"-"`
}

// DiffResult describes what changed between two snapshots.
type DiffResult struct {
	New     []SnapshotFinding `json:"new"`
	Fixed   []SnapshotFinding `json:"fixed"`
	Unchanged int             `json:"unchanged"`
}

func Migrate(db *gorm.DB) error {
	return db.AutoMigrate(&ScanSnapshot{})
}

// Save captures a new snapshot for the given asset.
func Save(db *gorm.DB, snap *ScanSnapshot, findings []SnapshotFinding) error {
	b, err := json.Marshal(findings)
	if err != nil {
		return err
	}
	snap.FindingsJSON = string(b)
	snap.VulnCount = len(findings)
	return db.Create(snap).Error
}

// ListByAsset returns snapshots for an asset, newest first.
func ListByAsset(db *gorm.DB, assetID uint, limit int) ([]ScanSnapshot, error) {
	var out []ScanSnapshot
	q := db.Where("asset_id = ? AND deleted_at IS NULL", assetID).Order("scanned_at desc")
	if limit > 0 {
		q = q.Limit(limit)
	}
	return out, q.Find(&out).Error
}

// GetByID returns a single snapshot with its findings.
func GetByID(db *gorm.DB, id uint) (*ScanSnapshot, []SnapshotFinding, error) {
	var snap ScanSnapshot
	if err := db.First(&snap, id).Error; err != nil {
		return nil, nil, err
	}
	var findings []SnapshotFinding
	if snap.FindingsJSON != "" {
		json.Unmarshal([]byte(snap.FindingsJSON), &findings) //nolint:errcheck
	}
	return &snap, findings, nil
}

// Diff compares two snapshots and returns new/fixed findings.
func Diff(olderFindings, newerFindings []SnapshotFinding) DiffResult {
	key := func(f SnapshotFinding) string {
		return f.TargetValue + "|" + f.Name + "|" + f.TemplateID + "|" + f.CveID
	}
	olderSet := map[string]bool{}
	for _, f := range olderFindings {
		olderSet[key(f)] = true
	}
	newerSet := map[string]bool{}
	for _, f := range newerFindings {
		newerSet[key(f)] = true
	}

	var result DiffResult
	for _, f := range newerFindings {
		if olderSet[key(f)] {
			result.Unchanged++
		} else {
			result.New = append(result.New, f)
		}
	}
	for _, f := range olderFindings {
		if !newerSet[key(f)] {
			result.Fixed = append(result.Fixed, f)
		}
	}
	return result
}

// Delete removes a snapshot.
func Delete(db *gorm.DB, id uint) error {
	return db.Delete(&ScanSnapshot{}, id).Error
}

// PruneOld keeps only the most recent `keep` snapshots per asset.
func PruneOld(db *gorm.DB, assetID uint, keep int) error {
	var snaps []ScanSnapshot
	if err := db.Where("asset_id = ? AND deleted_at IS NULL", assetID).
		Order("scanned_at desc").Find(&snaps).Error; err != nil {
		return err
	}
	if len(snaps) <= keep {
		return nil
	}
	for _, s := range snaps[keep:] {
		db.Delete(&ScanSnapshot{}, s.ID) //nolint:errcheck
	}
	return nil
}
