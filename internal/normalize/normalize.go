package normalize

import (
	"fmt"
	"strings"

	"github.com/auditvision/internal/model"
)

// Event converts a raw AuditEvent into a NormalizedEvent.
// It does NOT enrich with deployment diff — that is handled by the enrich package.
func Event(ev model.AuditEvent) model.NormalizedEvent {
	sourceIP := ""
	if len(ev.SourceIPs) > 0 {
		sourceIP = ev.SourceIPs[0]
	}

	ne := model.NormalizedEvent{
		AuditID:     ev.AuditID,
		Timestamp:   ev.StageTimestamp,
		Actor:       ev.User.Username,
		ActorType:   ActorType(ev.User.Username),
		Source:      Source(ev.UserAgent, ev.User.Username),
		SourceIP:    sourceIP,
		UserAgent:   ev.UserAgent,
		Verb:        ev.Verb,
		Resource:    ev.ObjectRef.Resource,
		Subresource: ev.ObjectRef.Subresource,
		APIGroup:    ev.ObjectRef.APIGroup,
		APIVersion:  ev.ObjectRef.APIVersion,
		Namespace:   ev.ObjectRef.Namespace,
		Name:        ev.ObjectRef.Name,
		Result:      ev.ResponseStatus.Code,
		Decision:    ev.Annotations["authorization.k8s.io/decision"],
		Reason:      ev.Annotations["authorization.k8s.io/reason"],
		Stage:       ev.Stage,
		Level:       ev.Level,
		RequestURI:  ev.RequestURI,
	}

	ne.ActionSummary = ActionSummary(ne)
	return ne
}

// ActorType classifies a username into human | serviceaccount | system.
func ActorType(username string) string {
	switch {
	case strings.HasPrefix(username, "system:serviceaccount:"):
		return "serviceaccount"
	// system:admin and system:masters are real human admins, not system components
	case username == "system:admin" || username == "system:masters":
		return "human"
	case strings.HasPrefix(username, "system:"):
		return "system"
	default:
		return "human"
	}
}

// Source classifies the origin of a request based on User-Agent and username.
func Source(userAgent, username string) string {
	ua := strings.ToLower(userAgent)
	switch {
	// OpenShift/Kubernetes web console
	case strings.Contains(ua, "console.openshift.io"),
		strings.Contains(ua, "openshift-console"),
		strings.Contains(ua, "mozilla/"),
		strings.Contains(ua, "chrome/"),
		strings.Contains(ua, "safari/"):
		return "console"
	// CLI tools
	case strings.Contains(ua, "kubectl"),
		strings.Contains(ua, "oc/"),
		strings.HasPrefix(ua, "oc "),
		strings.Contains(ua, "openshift-client"):
		return "cli"
	case strings.Contains(ua, "terraform"):
		return "terraform"
	case strings.Contains(ua, "argocd"), strings.Contains(ua, "argo-cd"):
		return "gitops"
	case strings.Contains(ua, "operator"), strings.Contains(ua, "controller-runtime"):
		return "operator"
	case strings.Contains(ua, "catalog/"):
		return "operator"
	case strings.HasPrefix(username, "system:serviceaccount:"):
		return "serviceaccount"
	case strings.HasPrefix(username, "system:"):
		return "system"
	// Human user with unrecognised UA — likely API/script
	case ActorType(username) == "human" && username != "":
		return "api"
	default:
		return "unknown"
	}
}

// ActionSummary builds a human-readable one-liner for an event.
func ActionSummary(ne model.NormalizedEvent) string {
	resource := ne.Resource
	if ne.Name != "" {
		resource = fmt.Sprintf("%s/%s", ne.Resource, ne.Name)
	}
	isScale := ne.Subresource == "scale" || strings.Contains(ne.RequestURI, "/scale")

	switch strings.ToLower(ne.Verb) {
	case "create":
		return fmt.Sprintf("%s created %s", ne.Actor, resource)
	case "update", "patch":
		if ne.Resource == "deployments" && isScale {
			return fmt.Sprintf("%s scaled %s", ne.Actor, resource)
		}
		return fmt.Sprintf("%s updated %s", ne.Actor, resource)
	case "delete":
		return fmt.Sprintf("%s deleted %s", ne.Actor, resource)
	default:
		return fmt.Sprintf("%s %s %s", ne.Actor, ne.Verb, resource)
	}
}

// IsInterestingVerb returns true for mutation verbs we care about.
func IsInterestingVerb(verb string) bool {
	switch strings.ToLower(verb) {
	case "create", "update", "patch", "delete", "deletecollection":
		return true
	}
	return false
}

// IsNoisyResource returns true for high-volume low-signal resources.
func IsNoisyResource(resource string) bool {
	switch strings.ToLower(resource) {
	case "leases",
		"subjectaccessreviews",
		"selfsubjectaccessreviews",
		"selfsubjectrulesreviews",
		"tokenreviews":
		return true
	}
	return false
}
