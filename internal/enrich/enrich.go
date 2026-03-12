package enrich

import (
    "context"
    "encoding/json"
    "fmt"
    "log"
    "strconv"
    "strings"

    "github.com/auditvision/internal/model"
)

// SnapshotStore is the minimal interface the enricher needs.
type SnapshotStore interface {
    GetSnapshot(ctx context.Context, namespace, name string) (*model.DeploymentSnapshot, error)
    SetSnapshot(ctx context.Context, snap model.DeploymentSnapshot) error
    DeleteSnapshot(ctx context.Context, namespace, name string) error
    GetConfigMapSnapshot(ctx context.Context, namespace, name string) (map[string]string, error)
    SetConfigMapSnapshot(ctx context.Context, namespace, name string, data map[string]string) error
    DeleteConfigMapSnapshot(ctx context.Context, namespace, name string) error
}

// Enricher enriches NormalizedEvents with deployment diff information.
type Enricher struct {
    store SnapshotStore
}

func New(store SnapshotStore) *Enricher {
    return &Enricher{store: store}
}

// Enrich mutates ne in place, adding Changes and a richer ActionSummary
// for workload events. It reads/writes snapshots via the store.
func (e *Enricher) Enrich(ctx context.Context, ne *model.NormalizedEvent, rawRequest *json.RawMessage) {
    switch ne.Resource {
    case "deployments", "statefulsets", "daemonsets":
	if ne.Namespace == "" || ne.Name == "" {
	    return
	}
	verb := strings.ToLower(ne.Verb)
	isScale := ne.Subresource == "scale" || strings.Contains(ne.RequestURI, "/scale")
	switch verb {
	case "create":
	    e.handleCreate(ctx, ne)
	case "update", "patch":
	    e.handleMutation(ctx, ne, rawRequest, isScale)
	case "delete":
	    e.handleDelete(ctx, ne)
	}

    case "configmaps":
	e.enrichConfigMap(ctx, ne, rawRequest, false)

    case "secrets":
	e.enrichConfigMap(ctx, ne, rawRequest, true)

    case "services":
	enrichService(ne, rawRequest)

    case "routes":
	enrichRoute(ne, rawRequest)

    case "horizontalpodautoscalers":
	e.enrichHPA(ctx, ne, rawRequest)
    }
}

// ─────────────────────────────────────────────────────────────────────────────

func (e *Enricher) handleCreate(ctx context.Context, ne *model.NormalizedEvent) {
    ne.ActionSummary = fmt.Sprintf("%s created %s/%s", ne.Actor, ne.Resource, ne.Name)
}

func (e *Enricher) handleMutation(ctx context.Context, ne *model.NormalizedEvent, rawRequest *json.RawMessage, isScale bool) {
    // Step 1: load OLD snapshot from store
    oldSnap, err := e.store.GetSnapshot(ctx, ne.Namespace, ne.Name)
    if err != nil {
	log.Printf("enrich: get snapshot %s/%s: %v", ne.Namespace, ne.Name, err)
    }

    // Step 2: extract NEW values from the requestObject, comparing against old snapshot
    fromRequest := extractChangesFromRequest(rawRequest, ne.Subresource, oldSnap)

    // Step 3: merge old values into the change list for replicas/image
    if len(fromRequest) > 0 {
	if oldSnap != nil {
	    for i, ch := range fromRequest {
		if ch.Field == "spec.replicas" {
		    fromRequest[i].Old = fmt.Sprintf("%d", oldSnap.Replicas)
		}
		for cname, oldImage := range oldSnap.Containers {
		    if strings.Contains(ch.Field, fmt.Sprintf("[%s].image", cname)) {
			fromRequest[i].Old = oldImage
		    }
		}
	    }
	}
	ne.Changes = fromRequest
    }

    // Step 4: update snapshot in store from the request data
    if len(fromRequest) > 0 && oldSnap != nil {
	updated := applyChangesToSnapshot(*oldSnap, fromRequest, rawRequest)
	if err := e.store.SetSnapshot(ctx, updated); err != nil {
	    log.Printf("enrich: set snapshot %s/%s: %v", ne.Namespace, ne.Name, err)
	}
    }

    // Step 5: build action summary
    onlyReplicas := len(ne.Changes) == 1 && ne.Changes[0].Field == "spec.replicas"
    if isScale || onlyReplicas {
	oldR, newR := "?", "?"
	for _, ch := range ne.Changes {
	    if ch.Field == "spec.replicas" {
		if ch.Old != "" {
		    oldR = ch.Old
		}
		newR = ch.New
	    }
	}
	ne.ActionSummary = fmt.Sprintf("%s scaled %s/%s (%s -> %s replicas)",
	    ne.Actor, ne.Resource, ne.Name, oldR, newR)
    } else {
	ne.ActionSummary = fmt.Sprintf("%s updated %s/%s (%d field(s) changed)",
	    ne.Actor, ne.Resource, ne.Name, len(ne.Changes))
    }
}


func (e *Enricher) handleDelete(ctx context.Context, ne *model.NormalizedEvent) {
    ne.ActionSummary = fmt.Sprintf("%s deleted %s/%s", ne.Actor, ne.Resource, ne.Name)
    if err := e.store.DeleteSnapshot(ctx, ne.Namespace, ne.Name); err != nil {
	log.Printf("enrich: delete snapshot %s/%s: %v", ne.Namespace, ne.Name, err)
    }
}

// ─────────────────────────────────────────────────────────────────────────────
// Parse requestObject
// ─────────────────────────────────────────────────────────────────────────────

func extractChangesFromRequest(raw *json.RawMessage, subresource string, oldSnap *model.DeploymentSnapshot) []model.ChangeItem {
    if raw == nil {
	return nil
    }

    // Scale subresource: {"spec":{"replicas":N}}
    if subresource == "scale" {
	var s model.ScalePatch
	if err := json.Unmarshal(*raw, &s); err == nil && s.Spec.Replicas != nil {
	    return []model.ChangeItem{{
		Field: "spec.replicas",
		New:   fmt.Sprintf("%d", *s.Spec.Replicas),
	    }}
	}
	return nil
    }

    var p model.DeploymentPatch
    if err := json.Unmarshal(*raw, &p); err != nil || p.Spec == nil {
	return nil
    }

    var changes []model.ChangeItem

    // ── replicas ──────────────────────────────────────────────────────────────
    if p.Spec.Replicas != nil {
	changes = append(changes, model.ChangeItem{
	    Field: "spec.replicas",
	    New:   fmt.Sprintf("%d", *p.Spec.Replicas),
	})
    }

    // ── strategy ──────────────────────────────────────────────────────────────
    if p.Spec.Strategy != nil {
	if p.Spec.Strategy.Type != "" {
	    changes = append(changes, model.ChangeItem{
		Field: "spec.strategy.type",
		New:   p.Spec.Strategy.Type,
	    })
	}
	if ru := p.Spec.Strategy.RollingUpdate; ru != nil {
	    if ru.MaxSurge != nil {
		changes = append(changes, model.ChangeItem{
		    Field: "spec.strategy.rollingUpdate.maxSurge",
		    New:   fmt.Sprintf("%d", *ru.MaxSurge),
		})
	    }
	    if ru.MaxUnavailable != nil {
		changes = append(changes, model.ChangeItem{
		    Field: "spec.strategy.rollingUpdate.maxUnavailable",
		    New:   fmt.Sprintf("%d", *ru.MaxUnavailable),
		})
	    }
	}
    }

    // ── misc spec fields ──────────────────────────────────────────────────────
    if p.Spec.MinReadySeconds != nil {
	changes = append(changes, model.ChangeItem{
	    Field: "spec.minReadySeconds",
	    New:   fmt.Sprintf("%d", *p.Spec.MinReadySeconds),
	})
    }
    if p.Spec.ProgressDeadlineSeconds != nil {
	changes = append(changes, model.ChangeItem{
	    Field: "spec.progressDeadlineSeconds",
	    New:   fmt.Sprintf("%d", *p.Spec.ProgressDeadlineSeconds),
	})
    }

    // ── top-level metadata labels/annotations ─────────────────────────────────
    if p.Metadata != nil {
	for k, v := range p.Metadata.Labels {
	    changes = append(changes, model.ChangeItem{
		Field: fmt.Sprintf("metadata.labels[%s]", k),
		New:   v,
	    })
	}
	for k, v := range p.Metadata.Annotations {
	    // skip noisy internal annotations
	    if strings.HasPrefix(k, "kubectl.kubernetes.io") ||
		strings.HasPrefix(k, "deployment.kubernetes.io") {
		continue
	    }
	    changes = append(changes, model.ChangeItem{
		Field: fmt.Sprintf("metadata.annotations[%s]", k),
		New:   v,
	    })
	}
    }

    if p.Spec.Template == nil {
	return changes
    }

    // ── pod template metadata ─────────────────────────────────────────────────
    if p.Spec.Template.Metadata != nil {
	for k, v := range p.Spec.Template.Metadata.Labels {
	    changes = append(changes, model.ChangeItem{
		Field: fmt.Sprintf("template.labels[%s]", k),
		New:   v,
	    })
	}
	for k, v := range p.Spec.Template.Metadata.Annotations {
	    if strings.HasPrefix(k, "kubectl.kubernetes.io") {
		continue
	    }
	    changes = append(changes, model.ChangeItem{
		Field: fmt.Sprintf("template.annotations[%s]", k),
		New:   v,
	    })
	}
    }

    if p.Spec.Template.Spec == nil {
	return changes
    }

    tspec := p.Spec.Template.Spec

    // ── serviceAccountName ────────────────────────────────────────────────────
    if tspec.ServiceAccountName != "" {
	changes = append(changes, model.ChangeItem{
	    Field: "spec.serviceAccountName",
	    New:   tspec.ServiceAccountName,
	})
    }

    // ── nodeSelector ──────────────────────────────────────────────────────────
    for k, v := range tspec.NodeSelector {
	changes = append(changes, model.ChangeItem{
	    Field: fmt.Sprintf("spec.nodeSelector[%s]", k),
	    New:   v,
	})
    }

    // ── volumes ───────────────────────────────────────────────────────────────
    for _, vol := range tspec.Volumes {
	changes = append(changes, model.ChangeItem{
	    Field: fmt.Sprintf("spec.volumes[%s]", vol.Name),
	    New:   "present",
	})
    }

    // ── containers (and initContainers) ──────────────────────────────────────
    allContainers := append(tspec.Containers, tspec.InitContainers...)
    for _, c := range allContainers {
	prefix := fmt.Sprintf("containers[%s]", c.Name)
	if len(tspec.InitContainers) > 0 {
	    // distinguish init containers in field name
	    for _, ic := range tspec.InitContainers {
		if ic.Name == c.Name {
		    prefix = fmt.Sprintf("initContainers[%s]", c.Name)
		}
	    }
	}

	if c.Image != "" {
	    changes = append(changes, model.ChangeItem{
		Field: prefix + ".image",
		New:   c.Image,
	    })
	}

	// resources.requests
	for res, val := range c.Resources.Requests {
	    key := c.Name + "/requests." + res
	    oldVal := ""
	    if oldSnap != nil && oldSnap.Resources != nil {
		oldVal = oldSnap.Resources[key]
	    }
	    if oldVal != val {
		changes = append(changes, model.ChangeItem{
		    Field: fmt.Sprintf("%s.resources.requests.%s", prefix, res),
		    Old:   oldVal,
		    New:   val,
		})
	    }
	}
	// resources.limits
	for res, val := range c.Resources.Limits {
	    key := c.Name + "/limits." + res
	    oldVal := ""
	    if oldSnap != nil && oldSnap.Resources != nil {
		oldVal = oldSnap.Resources[key]
	    }
	    if oldVal != val {
		changes = append(changes, model.ChangeItem{
		    Field: fmt.Sprintf("%s.resources.limits.%s", prefix, res),
		    Old:   oldVal,
		    New:   val,
		})
	    }
	}

	// volumeMounts
	for _, vm := range c.VolumeMounts {
	    changes = append(changes, model.ChangeItem{
		Field: fmt.Sprintf("%s.volumeMounts[%s]", prefix, vm.Name),
		New:   vm.MountPath,
	    })
	}

	// env — only changed vars vs snapshot
	for _, env := range c.Env {
	    key := c.Name + "/" + env.Name
	    oldVal := ""
	    if oldSnap != nil && oldSnap.Env != nil {
		oldVal = oldSnap.Env[key]
	    }
	    if oldVal != env.Value {
		changes = append(changes, model.ChangeItem{
		    Field: fmt.Sprintf("env[%s]", env.Name),
		    Old:   oldVal,
		    New:   env.Value,
		})
	    }
	}
    }

    return changes
}

// applyChangesToSnapshot creates an updated snapshot by applying a change list.
func applyChangesToSnapshot(snap model.DeploymentSnapshot, changes []model.ChangeItem, rawRequest *json.RawMessage) model.DeploymentSnapshot {
    updated := model.DeploymentSnapshot{
	Namespace:  snap.Namespace,
	Name:       snap.Name,
	Replicas:   snap.Replicas,
	Containers: make(map[string]string),
	Env:        make(map[string]string),
	Resources:  make(map[string]string),
    }
    for k, v := range snap.Containers {
	updated.Containers[k] = v
    }
    for k, v := range snap.Env {
	updated.Env[k] = v
    }
    for k, v := range snap.Resources {
	updated.Resources[k] = v
    }
    for _, ch := range changes {
	if ch.Field == "spec.replicas" {
	    if n, err := strconv.ParseInt(ch.New, 10, 32); err == nil {
		updated.Replicas = int32(n)
	    }
	}
	for cname := range updated.Containers {
	    if strings.Contains(ch.Field, fmt.Sprintf("[%s].image", cname)) {
		updated.Containers[cname] = ch.New
	    }
	}
    }
    // Update env and resources from rawRequest for future diffs
    if rawRequest != nil {
	var p model.DeploymentPatch
	if err := json.Unmarshal(*rawRequest, &p); err == nil && p.Spec != nil &&
	    p.Spec.Template != nil && p.Spec.Template.Spec != nil {
	    for _, c := range p.Spec.Template.Spec.Containers {
		for _, env := range c.Env {
		    updated.Env[c.Name+"/"+env.Name] = env.Value
		}
		for res, val := range c.Resources.Requests {
		    updated.Resources[c.Name+"/requests."+res] = val
		}
		for res, val := range c.Resources.Limits {
		    updated.Resources[c.Name+"/limits."+res] = val
		}
	    }
	}
    }
    return updated
}

// CompareSnapshots diffs two snapshots — used as fallback when requestObject is nil.
func CompareSnapshots(oldSnap, newSnap model.DeploymentSnapshot) []model.ChangeItem {
    var changes []model.ChangeItem

    if oldSnap.Replicas != newSnap.Replicas {
	changes = append(changes, model.ChangeItem{
	    Field: "spec.replicas",
	    Old:   fmt.Sprintf("%d", oldSnap.Replicas),
	    New:   fmt.Sprintf("%d", newSnap.Replicas),
	})
    }

    seen := map[string]bool{}
    for name, oldImage := range oldSnap.Containers {
	seen[name] = true
	newImage, ok := newSnap.Containers[name]
	if !ok {
	    changes = append(changes, model.ChangeItem{
		Field: fmt.Sprintf("spec.template.spec.containers[%s]", name),
		Old:   oldImage,
		New:   "<removed>",
	    })
	    continue
	}
	if oldImage != newImage {
	    changes = append(changes, model.ChangeItem{
		Field: fmt.Sprintf("spec.template.spec.containers[%s].image", name),
		Old:   oldImage,
		New:   newImage,
	    })
	}
    }
    for name, newImage := range newSnap.Containers {
	if !seen[name] {
	    changes = append(changes, model.ChangeItem{
		Field: fmt.Sprintf("spec.template.spec.containers[%s]", name),
		Old:   "<missing>",
		New:   newImage,
	    })
	}
    }
    return changes
}

// ─────────────────────────────────────────────────────────────────────────────
// ConfigMap / Secret enrichment
// ─────────────────────────────────────────────────────────────────────────────

func (e *Enricher) enrichConfigMap(ctx context.Context, ne *model.NormalizedEvent, raw *json.RawMessage, redactValues bool) {
    verb := strings.ToLower(ne.Verb)

    if verb == "delete" {
	ne.ActionSummary = fmt.Sprintf("%s deleted %s/%s", ne.Actor, ne.Resource, ne.Name)
	_ = e.store.DeleteConfigMapSnapshot(ctx, ne.Namespace, ne.Name)
	return
    }

    if raw == nil {
	if redactValues {
	    ne.Changes = []model.ChangeItem{{Field: "[not logged — platform security policy]"}}
	}
	return
    }

    // Parse incoming data from requestObject
    var obj struct {
	Data       map[string]string `json:"data"`
	BinaryData map[string]string `json:"binaryData"`
	StringData map[string]string `json:"stringData"`
    }
    if err := json.Unmarshal(*raw, &obj); err != nil {
	return
    }

    newData := map[string]string{}
    for k, v := range obj.Data {
	newData[k] = v
    }
    for k, v := range obj.StringData {
	newData[k] = v
    }
    for k := range obj.BinaryData {
	newData[k] = "<binary>"
    }

    // Load old snapshot for diff
    oldData, _ := e.store.GetConfigMapSnapshot(ctx, ne.Namespace, ne.Name)

    var changes []model.ChangeItem

    // Keys present in new data — added or changed
    for k, newVal := range newData {
	oldVal := ""
	if oldData != nil {
	    oldVal = oldData[k]
	}
	ch := model.ChangeItem{Field: fmt.Sprintf("data[%s]", k)}
	if redactValues {
	    if oldVal != "" {
		ch.Old = "<redacted>"
	    }
	    ch.New = "<redacted>"
	} else {
	    ch.Old = truncate(oldVal, 120)
	    ch.New = truncate(newVal, 120)
	}
	// Only show if actually changed (or new key)
	if ch.Old != ch.New {
	    changes = append(changes, ch)
	}
    }

    // Keys removed (present in old but not in new patch)
    // Note: strategic merge patch only sends changed keys, so we skip removal detection
    // for patch verb — only show it for full update (PUT)
    if verb == "update" && oldData != nil {
	for k, oldVal := range oldData {
	    if _, exists := newData[k]; !exists {
		ch := model.ChangeItem{
		    Field: fmt.Sprintf("data[%s]", k),
		    New:   "<removed>",
		}
		if redactValues {
		    ch.Old = "<redacted>"
		} else {
		    ch.Old = truncate(oldVal, 120)
		}
		changes = append(changes, ch)
	    }
	}
    }

    ne.Changes = changes

    switch verb {
    case "create":
	ne.ActionSummary = fmt.Sprintf("%s created %s/%s (%d key(s))",
	    ne.Actor, ne.Resource, ne.Name, len(newData))
    case "update", "patch":
	ne.ActionSummary = fmt.Sprintf("%s updated %s/%s (%d key(s) changed)",
	    ne.Actor, ne.Resource, ne.Name, len(changes))
    }

    // Save snapshot — merge new keys into old state
    merged := map[string]string{}
    for k, v := range oldData {
	merged[k] = v
    }
    for k, v := range newData {
	merged[k] = v
    }
    _ = e.store.SetConfigMapSnapshot(ctx, ne.Namespace, ne.Name, merged)
}

func truncate(s string, n int) string {
    if len(s) > n {
	return s[:n] + "…"
    }
    return s
}

// ─────────────────────────────────────────────────────────────────────────────
// Service enrichment
// ─────────────────────────────────────────────────────────────────────────────

func enrichService(ne *model.NormalizedEvent, raw *json.RawMessage) {
    verb := strings.ToLower(ne.Verb)
    if verb == "delete" {
	ne.ActionSummary = fmt.Sprintf("%s deleted service/%s", ne.Actor, ne.Name)
	return
    }
    if raw == nil {
	return
    }

    var svc struct {
	Spec *struct {
	    Type      string `json:"type"`
	    ClusterIP string `json:"clusterIP"`
	    Selector  map[string]string `json:"selector"`
	    Ports     []struct {
		Name       string `json:"name"`
		Port       int    `json:"port"`
		TargetPort interface{} `json:"targetPort"`
		Protocol   string `json:"protocol"`
		NodePort   int    `json:"nodePort"`
	    } `json:"ports"`
	} `json:"spec"`
    }
    if err := json.Unmarshal(*raw, &svc); err != nil || svc.Spec == nil {
	return
    }

    var changes []model.ChangeItem

    if svc.Spec.Type != "" {
	changes = append(changes, model.ChangeItem{
	    Field: "spec.type",
	    New:   svc.Spec.Type,
	})
    }

    for _, p := range svc.Spec.Ports {
	name := p.Name
	if name == "" {
	    name = fmt.Sprintf("%d", p.Port)
	}
	portStr := fmt.Sprintf("%d/%s", p.Port, p.Protocol)
	targetStr := ""
	if p.TargetPort != nil {
	    targetStr = fmt.Sprintf("%v", p.TargetPort)
	}
	// Only show arrow if targetPort differs from port
	if targetStr != "" && targetStr != fmt.Sprintf("%d", p.Port) {
	    portStr += fmt.Sprintf(" → %s", targetStr)
	}
	if p.NodePort != 0 {
	    portStr += fmt.Sprintf(" (nodePort:%d)", p.NodePort)
	}
	changes = append(changes, model.ChangeItem{
	    Field: fmt.Sprintf("spec.ports[%s]", name),
	    New:   portStr,
	})
    }

    for k, v := range svc.Spec.Selector {
	changes = append(changes, model.ChangeItem{
	    Field: fmt.Sprintf("spec.selector[%s]", k),
	    New:   v,
	})
    }

    ne.Changes = changes
    switch verb {
    case "create":
	ne.ActionSummary = fmt.Sprintf("%s created service/%s", ne.Actor, ne.Name)
    default:
	ne.ActionSummary = fmt.Sprintf("%s updated service/%s (%d field(s) changed)",
	    ne.Actor, ne.Name, len(changes))
    }
}

// ─────────────────────────────────────────────────────────────────────────────
// Route enrichment (OpenShift)
// ─────────────────────────────────────────────────────────────────────────────

func enrichRoute(ne *model.NormalizedEvent, raw *json.RawMessage) {
    verb := strings.ToLower(ne.Verb)
    if verb == "delete" {
	ne.ActionSummary = fmt.Sprintf("%s deleted route/%s", ne.Actor, ne.Name)
	return
    }
    if raw == nil {
	ne.Changes = []model.ChangeItem{{Field: "[not logged — platform security policy]"}}
	return
    }

    var route struct {
	Metadata *struct {
	    Name string `json:"name"`
	} `json:"metadata"`
	Spec *struct {
	    Host string `json:"host"`
	    Path string `json:"path"`
	    To   *struct {
		Name   string `json:"name"`
		Weight *int   `json:"weight"`
	    } `json:"to"`
	    Port *struct {
		TargetPort interface{} `json:"targetPort"`
	    } `json:"port"`
	    TLS *struct {
		Termination string `json:"termination"`
	    } `json:"tls"`
	    WildcardPolicy string `json:"wildcardPolicy"`
	} `json:"spec"`
    }
    if err := json.Unmarshal(*raw, &route); err != nil || route.Spec == nil {
	return
    }

    // Name may be empty on CREATE (POST to collection) — fall back to metadata.name from body
    displayName := ne.Name
    if displayName == "" && route.Metadata != nil {
	displayName = route.Metadata.Name
    }

    var changes []model.ChangeItem
    s := route.Spec

    if s.Host != "" {
	changes = append(changes, model.ChangeItem{Field: "spec.host", New: s.Host})
    }
    if s.Path != "" {
	changes = append(changes, model.ChangeItem{Field: "spec.path", New: s.Path})
    }
    if s.To != nil && s.To.Name != "" {
	val := s.To.Name
	if s.To.Weight != nil {
	    val += fmt.Sprintf(" (weight:%d)", *s.To.Weight)
	}
	changes = append(changes, model.ChangeItem{Field: "spec.to", New: val})
    }
    if s.Port != nil && s.Port.TargetPort != nil {
	changes = append(changes, model.ChangeItem{
	    Field: "spec.port.targetPort",
	    New:   fmt.Sprintf("%v", s.Port.TargetPort),
	})
    }
    if s.TLS != nil && s.TLS.Termination != "" {
	changes = append(changes, model.ChangeItem{
	    Field: "spec.tls.termination",
	    New:   s.TLS.Termination,
	})
    }
    if s.WildcardPolicy != "" && s.WildcardPolicy != "None" {
	changes = append(changes, model.ChangeItem{
	    Field: "spec.wildcardPolicy",
	    New:   s.WildcardPolicy,
	})
    }

    ne.Changes = changes
    switch verb {
    case "create":
	ne.ActionSummary = fmt.Sprintf("%s created route/%s → %s", ne.Actor, displayName, s.Host)
    default:
	ne.ActionSummary = fmt.Sprintf("%s updated route/%s (%d field(s) changed)",
	    ne.Actor, displayName, len(changes))
    }
}

// ─────────────────────────────────────────────────────────────────────────────
// HPA enrichment
// ─────────────────────────────────────────────────────────────────────────────

func (e *Enricher) enrichHPA(ctx context.Context, ne *model.NormalizedEvent, raw *json.RawMessage) {
    verb := strings.ToLower(ne.Verb)
    if verb == "delete" {
	ne.ActionSummary = fmt.Sprintf("%s deleted hpa/%s", ne.Actor, ne.Name)
	// reuse configmap snapshot store with "hpa:" prefix
	_ = e.store.DeleteConfigMapSnapshot(ctx, ne.Namespace, "hpa:"+ne.Name)
	return
    }
    if raw == nil {
	return
    }

    var hpa struct {
	Spec *struct {
	    MinReplicas    *int32 `json:"minReplicas"`
	    MaxReplicas    int32  `json:"maxReplicas"`
	    ScaleTargetRef *struct {
		Kind string `json:"kind"`
		Name string `json:"name"`
	    } `json:"scaleTargetRef"`
	    Metrics []struct {
		Type     string `json:"type"`
		Resource *struct {
		    Name   string `json:"name"`
		    Target *struct {
			Type               string `json:"type"`
			AverageUtilization *int32 `json:"averageUtilization"`
			AverageValue       string `json:"averageValue"`
		    } `json:"target"`
		} `json:"resource"`
		Pods *struct {
		    Metric *struct{ Name string `json:"name"` } `json:"metric"`
		    Target *struct {
			AverageValue string `json:"averageValue"`
		    } `json:"target"`
		} `json:"pods"`
	    } `json:"metrics"`
	} `json:"spec"`
    }
    if err := json.Unmarshal(*raw, &hpa); err != nil || hpa.Spec == nil {
	return
    }

    s := hpa.Spec
    minR := int32(1)
    if s.MinReplicas != nil {
	minR = *s.MinReplicas
    }

    // Build flat map of current state for snapshot + diff
    newState := map[string]string{
	"spec.minReplicas": fmt.Sprintf("%d", minR),
	"spec.maxReplicas": fmt.Sprintf("%d", s.MaxReplicas),
    }
    if s.ScaleTargetRef != nil {
	newState["spec.scaleTargetRef"] = fmt.Sprintf("%s/%s", s.ScaleTargetRef.Kind, s.ScaleTargetRef.Name)
    }
    for _, m := range s.Metrics {
	switch m.Type {
	case "Resource":
	    if m.Resource != nil && m.Resource.Target != nil {
		t := m.Resource.Target
		val := ""
		if t.AverageUtilization != nil {
		    val = fmt.Sprintf("%d%%", *t.AverageUtilization)
		} else if t.AverageValue != "" {
		    val = t.AverageValue
		}
		key := fmt.Sprintf("metrics[%s].target.%s", m.Resource.Name, strings.ToLower(t.Type))
		newState[key] = val
	    }
	case "Pods":
	    if m.Pods != nil && m.Pods.Metric != nil && m.Pods.Target != nil {
		key := fmt.Sprintf("metrics[%s].averageValue", m.Pods.Metric.Name)
		newState[key] = m.Pods.Target.AverageValue
	    }
	}
    }

    // Load old snapshot
    oldState, _ := e.store.GetConfigMapSnapshot(ctx, ne.Namespace, "hpa:"+ne.Name)

    var changes []model.ChangeItem
    for field, newVal := range newState {
	oldVal := ""
	if oldState != nil {
	    oldVal = oldState[field]
	}
	// Skip fields with no old value that haven't changed (e.g. minReplicas default in patch)
	if oldVal == newVal {
	    continue
	}
	// Skip fields absent from snapshot on patch (not a real change, just patch defaults)
	if verb != "create" && oldVal == "" {
	    continue
	}
	changes = append(changes, model.ChangeItem{Field: field, Old: oldVal, New: newVal})
    }

    // On create show all fields even without old values
    if verb == "create" {
	changes = nil
	for field, newVal := range newState {
	    changes = append(changes, model.ChangeItem{Field: field, New: newVal})
	}
    }

    ne.Changes = changes

    target := ""
    if s.ScaleTargetRef != nil {
	target = fmt.Sprintf(" → %s/%s", s.ScaleTargetRef.Kind, s.ScaleTargetRef.Name)
    }
    switch verb {
    case "create":
	ne.ActionSummary = fmt.Sprintf("%s created hpa/%s%s (min:%d max:%d)",
	    ne.Actor, ne.Name, target, minR, s.MaxReplicas)
    default:
	ne.ActionSummary = fmt.Sprintf("%s updated hpa/%s (%d field(s) changed)",
	    ne.Actor, ne.Name, len(changes))
    }

    // Save snapshot — merge new into old
    merged := map[string]string{}
    for k, v := range oldState {
	merged[k] = v
    }
    for k, v := range newState {
	merged[k] = v
    }
    _ = e.store.SetConfigMapSnapshot(ctx, ne.Namespace, "hpa:"+ne.Name, merged)
}