package store

import (
	"context"
	"time"

	"github.com/auditvision/internal/model"
)

// Store is the main persistence interface.
type Store interface {
	EventStore
	SnapshotStore
	ConfigMapSnapshotStore
	ExclusionRuleStore
	Close()
}

// EventStore handles audit event persistence and querying.
type EventStore interface {
	InsertEvent(ctx context.Context, ev model.NormalizedEvent) error
	GetEvents(ctx context.Context, f model.EventFilter) ([]model.NormalizedEvent, error)
	GetEventByID(ctx context.Context, auditID string) (*model.NormalizedEvent, error)
	GetSummary(ctx context.Context, f model.EventFilter) (*model.SummaryResponse, error)
	CountEvents(ctx context.Context, f model.EventFilter) (int, error)
	PurgeOldEvents(ctx context.Context, olderThan time.Duration) (int64, error)
}

// SnapshotStore handles deployment/statefulset/daemonset state snapshots.
type SnapshotStore interface {
	GetSnapshot(ctx context.Context, namespace, name string) (*model.DeploymentSnapshot, error)
	SetSnapshot(ctx context.Context, snap model.DeploymentSnapshot) error
	DeleteSnapshot(ctx context.Context, namespace, name string) error
	BulkSetSnapshots(ctx context.Context, snaps []model.DeploymentSnapshot) error
}

// ConfigMapSnapshotStore handles ConfigMap and Secret key snapshots.
type ConfigMapSnapshotStore interface {
	GetConfigMapSnapshot(ctx context.Context, namespace, name string) (map[string]string, error)
	SetConfigMapSnapshot(ctx context.Context, namespace, name string, data map[string]string) error
	DeleteConfigMapSnapshot(ctx context.Context, namespace, name string) error
}

// ExclusionRuleStore manages exclusion rules used by the collector to drop events before storing.
type ExclusionRuleStore interface {
	GetExclusionRules(ctx context.Context) ([]model.ExclusionRule, error)
	InsertExclusionRule(ctx context.Context, r model.ExclusionRule) (model.ExclusionRule, error)
	UpdateExclusionRule(ctx context.Context, r model.ExclusionRule) error
	DeleteExclusionRule(ctx context.Context, id int64) error
}
