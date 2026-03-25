package schedules

import (
	"time"

	"gorm.io/gorm"
)

// ScheduleRecord stores a recurring scan schedule for an asset.
type ScheduleRecord struct {
	ID        uint           `gorm:"primaryKey;autoIncrement" json:"id"`
	AssetID   uint           `gorm:"not null;index" json:"asset_id"`
	AssetName string         `json:"asset_name"`
	Label     string         `json:"label"`      // human-readable: "Every 24h"
	IntervalH int            `json:"interval_h"` // hours between runs
	Enabled   bool           `gorm:"default:true" json:"enabled"`
	LastRunAt *time.Time     `json:"last_run_at"`
	NextRunAt time.Time      `gorm:"index" json:"next_run_at"`
	CreatedAt time.Time      `json:"created_at"`
	DeletedAt gorm.DeletedAt `gorm:"index" json:"-"`
}

func Migrate(db *gorm.DB) error {
	return db.AutoMigrate(&ScheduleRecord{})
}

func Create(db *gorm.DB, r *ScheduleRecord) error {
	return db.Create(r).Error
}

func List(db *gorm.DB) ([]ScheduleRecord, error) {
	var out []ScheduleRecord
	err := db.Where("deleted_at IS NULL").Order("next_run_at asc").Find(&out).Error
	return out, err
}

func ListDue(db *gorm.DB) ([]ScheduleRecord, error) {
	var out []ScheduleRecord
	err := db.Where("enabled = true AND next_run_at <= ? AND deleted_at IS NULL", time.Now()).Find(&out).Error
	return out, err
}

func MarkRan(db *gorm.DB, id uint) error {
	now := time.Now()
	return db.Model(&ScheduleRecord{}).Where("id = ?", id).Updates(map[string]any{
		"last_run_at": now,
	}).Error
}

func BumpNextRun(db *gorm.DB, id uint, intervalH int) error {
	next := time.Now().Add(time.Duration(intervalH) * time.Hour)
	return db.Model(&ScheduleRecord{}).Where("id = ?", id).Update("next_run_at", next).Error
}

func SetEnabled(db *gorm.DB, id uint, enabled bool) error {
	return db.Model(&ScheduleRecord{}).Where("id = ?", id).Update("enabled", enabled).Error
}

func Delete(db *gorm.DB, id uint) error {
	return db.Delete(&ScheduleRecord{}, id).Error
}

func GetByID(db *gorm.DB, id uint) (*ScheduleRecord, error) {
	var r ScheduleRecord
	err := db.First(&r, id).Error
	return &r, err
}
