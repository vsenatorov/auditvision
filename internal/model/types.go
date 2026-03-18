package model

import (
	"encoding/json"
	"time"
)

// ─────────────────────────────────────────────────────────────────────────────
// Raw audit event — exactly as kube-apiserver sends it
// ─────────────────────────────────────────────────────────────────────────────

type AuditUser struct {
	Username string   `json:"username"`
	Groups   []string `json:"groups"`
}

type AuditObjectRef struct {
	Resource    string `json:"resource"`
	Subresource string `json:"subresource"`
	Namespace   string `json:"namespace"`
	Name        string `json:"name"`
	APIGroup    string `json:"apiGroup"`
	APIVersion  string `json:"apiVersion"`
}

type AuditResponseStatus struct {
	Code int `json:"code"`
}

type AuditEvent struct {
	AuditID                  string              `json:"auditID"`
	Level                    string              `json:"level"`
	Stage                    string              `json:"stage"`
	Verb                     string              `json:"verb"`
	RequestURI               string              `json:"requestURI"`
	RequestReceivedTimestamp string              `json:"requestReceivedTimestamp"`
	StageTimestamp           string              `json:"stageTimestamp"`
	User                     AuditUser           `json:"user"`
	SourceIPs                []string            `json:"sourceIPs"`
	UserAgent                string              `json:"userAgent"`
	ObjectRef                AuditObjectRef      `json:"objectRef"`
	ResponseStatus           AuditResponseStatus `json:"responseStatus"`
	Annotations              map[string]string   `json:"annotations"`
	RequestObject            *json.RawMessage    `json:"requestObject,omitempty"`
}

type AuditEventList struct {
	Kind       string       `json:"kind"`
	APIVersion string       `json:"apiVersion"`
	Items      []AuditEvent `json:"items"`
}

// ─────────────────────────────────────────────────────────────────────────────
// Normalized / enriched event
// ─────────────────────────────────────────────────────────────────────────────

type ChangeItem struct {
	Field string `json:"field"`
	Old   string `json:"old,omitempty"`
	New   string `json:"new,omitempty"`
}

type NormalizedEvent struct {
	AuditID       string       `json:"auditID"`
	Timestamp     string       `json:"timestamp"`
	Actor         string       `json:"actor"`
	ActorType     string       `json:"actorType"`
	Source        string       `json:"source"`
	SourceIP      string       `json:"sourceIP,omitempty"`
	UserAgent     string       `json:"userAgent,omitempty"`
	Verb          string       `json:"verb"`
	Resource      string       `json:"resource"`
	Subresource   string       `json:"subresource,omitempty"`
	APIGroup      string       `json:"apiGroup,omitempty"`
	APIVersion    string       `json:"apiVersion,omitempty"`
	Namespace     string       `json:"namespace,omitempty"`
	Name          string       `json:"name,omitempty"`
	Result        int          `json:"result"`
	Decision      string       `json:"decision,omitempty"`
	Reason        string       `json:"reason,omitempty"`
	Stage         string       `json:"stage,omitempty"`
	Level         string       `json:"level,omitempty"`
	RequestURI    string       `json:"requestURI,omitempty"`
	ActionSummary string       `json:"actionSummary,omitempty"`
	Changes       []ChangeItem `json:"changes,omitempty"`
	RiskScore     string       `json:"riskScore,omitempty"`
	RiskReason    string       `json:"riskReason,omitempty"`
}

// ─────────────────────────────────────────────────────────────────────────────
// Deployment snapshot
// ─────────────────────────────────────────────────────────────────────────────

type DeploymentSnapshot struct {
	Namespace  string            `json:"namespace"`
	Name       string            `json:"name"`
	Replicas   int32             `json:"replicas"`
	Containers map[string]string `json:"containers"`
	Env        map[string]string `json:"env"`
	Resources  map[string]string `json:"resources"`
}

// ─────────────────────────────────────────────────────────────────────────────
// Query filters
// ─────────────────────────────────────────────────────────────────────────────

type EventFilter struct {
	Actor               string
	Namespace           string
	Resource            string
	Verb                string
	Source              string
	ActorType           string
	Name                string
	ResultCode          int
	InterestingOnly     bool
	HideServiceAccounts bool
	HumanOnly           bool
	From                string
	To                  string
	RiskScore           string
	Limit               int
	Offset              int
}

// ─────────────────────────────────────────────────────────────────────────────
// API responses
// ─────────────────────────────────────────────────────────────────────────────

type SummaryResponse struct {
	TotalEvents          int            `json:"totalEvents"`
	HumanEvents          int            `json:"humanEvents"`
	ServiceAccountEvents int            `json:"serviceAccountEvents"`
	SystemEvents         int            `json:"systemEvents"`
	TopActors            map[string]int `json:"topActors"`
	TopResources         map[string]int `json:"topResources"`
	TopVerbs             map[string]int `json:"topVerbs"`
	TopSources           map[string]int `json:"topSources"`
	TopNamespaces        map[string]int `json:"topNamespaces"`
	RecentErrors         []RecentError  `json:"recentErrors"`
	HourlyActivity       []HourlyBucket `json:"hourlyActivity"`
	MutationEvents       int            `json:"mutationEvents"`
	ErrorEvents          int            `json:"errorEvents"`
	RiskHigh             int            `json:"riskHigh"`
	RiskMedium           int            `json:"riskMedium"`
	RiskLow              int            `json:"riskLow"`
	RiskNotAnalyzed      int            `json:"riskNotAnalyzed"`
	TopRiskEvents        []RiskEvent    `json:"topRiskEvents"`
}

type RiskEvent struct {
	Timestamp     string `json:"timestamp"`
	Actor         string `json:"actor"`
	Verb          string `json:"verb"`
	Resource      string `json:"resource"`
	Name          string `json:"name"`
	Namespace     string `json:"namespace"`
	RiskScore     string `json:"riskScore"`
	RiskReason    string `json:"riskReason"`
	ActionSummary string `json:"actionSummary"`
	AuditID       string `json:"auditID"`
}

type RecentError struct {
	Timestamp     string `json:"timestamp"`
	Actor         string `json:"actor"`
	Verb          string `json:"verb"`
	Resource      string `json:"resource"`
	Name          string `json:"name"`
	Namespace     string `json:"namespace"`
	Result        int    `json:"result"`
	ActionSummary string `json:"actionSummary"`
	AuditID       string `json:"auditID"`
}

type HourlyBucket struct {
	Hour    string `json:"hour"`
	Total   int    `json:"total"`
	Creates int    `json:"creates"`
	Deletes int    `json:"deletes"`
	Updates int    `json:"updates"`
}

// ─────────────────────────────────────────────────────────────────────────────
// Exclusion Rules — collector drops matching events before storing
// ─────────────────────────────────────────────────────────────────────────────

// ExclusionRule defines a filter that prevents matching events from being stored.
// All non-empty fields must match (AND logic). Empty field = match any value.
type ExclusionRule struct {
	ID        int64     `json:"id"`
	Name      string    `json:"name"`
	Enabled   bool      `json:"enabled"`
	Namespace string    `json:"namespace"` // empty = any namespace
	Actor     string    `json:"actor"`     // supports * wildcard e.g. "system:serviceaccount:kube-*"
	ActorType string    `json:"actorType"` // human|serviceaccount|system|empty=any
	Verb      string    `json:"verb"`      // single or comma-separated: "get,list,watch"
	Resource  string    `json:"resource"`  // empty = any resource
	Comment   string    `json:"comment"`
	CreatedAt time.Time `json:"createdAt"`
}

// ─────────────────────────────────────────────────────────────────────────────
// Auth / Login events — captured from oauthaccesstokens + tokenrequests
// ─────────────────────────────────────────────────────────────────────────────

// AuthEvent represents a login, logout or failed auth attempt.
type AuthEvent struct {
	ID        int64  `json:"id"`
	Timestamp string `json:"timestamp"`
	Actor     string `json:"actor"`
	Method    string `json:"method"`   // web-console | oc-cli | api-token | unknown
	SourceIP  string `json:"sourceIP"`
	UserAgent string `json:"userAgent"`
	Result    int    `json:"result"`   // HTTP status code
	Success   bool   `json:"success"`
	EventType string `json:"eventType"` // login | logout | token-issued | token-revoked | failed
	AuditID   string `json:"auditID"`
}

// AuthEventFilter for querying auth_events.
type AuthEventFilter struct {
	Actor     string
	Method    string
	Success   *bool
	EventType string
	From      string
	To        string
	Limit     int
	Offset    int
}

// ─────────────────────────────────────────────────────────────────────────────
// Internal helpers for enrich package
// ─────────────────────────────────────────────────────────────────────────────

type ScalePatch struct {
	Spec struct {
		Replicas *int32 `json:"replicas"`
	} `json:"spec"`
}

type ContainerResources struct {
	Requests map[string]string `json:"requests"`
	Limits   map[string]string `json:"limits"`
}

type ContainerPatch struct {
	Name  string `json:"name"`
	Image string `json:"image"`
	Env   []struct {
		Name  string `json:"name"`
		Value string `json:"value"`
	} `json:"env"`
	Resources    ContainerResources `json:"resources"`
	VolumeMounts []struct {
		Name      string `json:"name"`
		MountPath string `json:"mountPath"`
	} `json:"volumeMounts"`
}

type DeploymentPatch struct {
	Metadata *struct {
		Labels      map[string]string `json:"labels"`
		Annotations map[string]string `json:"annotations"`
	} `json:"metadata"`
	Spec *struct {
		Replicas *int32 `json:"replicas"`
		Strategy *struct {
			Type          string `json:"type"`
			RollingUpdate *struct {
				MaxSurge       *int32 `json:"maxSurge"`
				MaxUnavailable *int32 `json:"maxUnavailable"`
			} `json:"rollingUpdate"`
		} `json:"strategy"`
		MinReadySeconds         *int32 `json:"minReadySeconds"`
		ProgressDeadlineSeconds *int32 `json:"progressDeadlineSeconds"`
		Template                *struct {
			Metadata *struct {
				Labels      map[string]string `json:"labels"`
				Annotations map[string]string `json:"annotations"`
			} `json:"metadata"`
			Spec *struct {
				Containers         []ContainerPatch  `json:"containers"`
				InitContainers     []ContainerPatch  `json:"initContainers"`
				Volumes            []struct{ Name string `json:"name"` } `json:"volumes"`
				ServiceAccountName string            `json:"serviceAccountName"`
				NodeSelector       map[string]string `json:"nodeSelector"`
			} `json:"spec"`
		} `json:"template"`
	} `json:"spec"`
}

type OcDeployment struct {
	Metadata struct {
		Namespace   string            `json:"namespace"`
		Name        string            `json:"name"`
		Labels      map[string]string `json:"labels"`
		Annotations map[string]string `json:"annotations"`
	} `json:"metadata"`
	Spec struct {
		Replicas *int32 `json:"replicas"`
		Strategy *struct {
			Type string `json:"type"`
		} `json:"strategy"`
		Template struct {
			Spec struct {
				Containers []struct {
					Name  string `json:"name"`
					Image string `json:"image"`
					Env   []struct {
						Name  string `json:"name"`
						Value string `json:"value"`
					} `json:"env"`
					Resources ContainerResources `json:"resources"`
				} `json:"containers"`
				ServiceAccountName string            `json:"serviceAccountName"`
				NodeSelector       map[string]string `json:"nodeSelector"`
			} `json:"spec"`
		} `json:"template"`
	} `json:"spec"`
}

type OcDeploymentList struct {
	Items []OcDeployment `json:"items"`
}

type VectorAuditEvent struct {
	AuditID                  string              `json:"auditID"`
	Timestamp                string              `json:"@timestamp"`
	Level                    string              `json:"level"`
	Stage                    string              `json:"stage"`
	Verb                     string              `json:"verb"`
	RequestURI               string              `json:"requestURI"`
	RequestReceivedTimestamp string              `json:"requestReceivedTimestamp"`
	StageTimestamp           string              `json:"stageTimestamp"`
	User                     AuditUser           `json:"user"`
	SourceIPs                []string            `json:"sourceIPs"`
	UserAgent                string              `json:"userAgent"`
	ObjectRef                AuditObjectRef      `json:"objectRef"`
	ResponseStatus           AuditResponseStatus `json:"responseStatus"`
	Annotations              map[string]string   `json:"annotations"`
	RequestObject            *json.RawMessage    `json:"requestObject,omitempty"`
	LogSource                string              `json:"log_source"`
	LogType                  string              `json:"log_type"`
	Hostname                 string              `json:"hostname"`
}
