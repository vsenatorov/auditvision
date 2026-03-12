IMAGE_REPO ?= docker.io/hybrid2k3
VERSION    ?= 0.1.0

COLLECTOR_IMG = $(IMAGE_REPO)/audit-collector:$(VERSION)
UI_IMG        = $(IMAGE_REPO)/audit-ui:$(VERSION)

# ── Development ───────────────────────────────────────────────────────────────

.PHONY: run-collector
run-collector: ## Run collector locally (needs DATABASE_URL env)
	go run ./cmd/collector

.PHONY: run-ui
run-ui: ## Run UI locally (needs DATABASE_URL env)
	go run ./cmd/ui

.PHONY: tidy
tidy:
	go mod tidy

.PHONY: fmt
fmt:
	gofmt -w ./...

.PHONY: vet
vet:
	go vet ./...

.PHONY: test
test:
	go test ./... -v

# ── Build ─────────────────────────────────────────────────────────────────────

.PHONY: build
build:
	CGO_ENABLED=0 GOOS=linux go build -o bin/collector ./cmd/collector
	CGO_ENABLED=0 GOOS=linux go build -o bin/ui        ./cmd/ui

# ── Container images ──────────────────────────────────────────────────────────

.PHONY: docker-build
docker-build:
	docker build -f Dockerfile.collector -t $(COLLECTOR_IMG) .
	docker build -f Dockerfile.ui        -t $(UI_IMG) .

.PHONY: docker-push
docker-push:
	docker push $(COLLECTOR_IMG)
	docker push $(UI_IMG)

# ── Deploy ────────────────────────────────────────────────────────────────────

.PHONY: deploy
deploy: ## Deploy everything to current OpenShift cluster
	oc apply -f deploy/00-namespace.yaml
	oc apply -f deploy/01-postgres.yaml
	oc apply -f deploy/02-collector.yaml
	oc apply -f deploy/03-ui.yaml
	@echo ""
	@echo "Waiting for postgres to be ready..."
	oc rollout status deployment/postgres -n audit-vision
	@echo ""
	@echo "Deploy complete. UI route:"
	oc get route audit-ui -n audit-vision -o jsonpath='{.spec.host}'
	@echo ""

.PHONY: undeploy
undeploy:
	oc delete namespace audit-vision --ignore-not-found

# ── Local Postgres for dev ────────────────────────────────────────────────────

.PHONY: dev-db
dev-db: ## Start a local Postgres via podman
	podman run -d --name auditvision-pg \
	  -e POSTGRES_USER=auditvision \
	  -e POSTGRES_PASSWORD=changeme \
	  -e POSTGRES_DB=auditvision \
	  -p 5432:5432 \
	  postgres:15-alpine
	@echo "DATABASE_URL=postgres://auditvision:changeme@localhost:5432/auditvision?sslmode=disable"

.PHONY: dev-db-stop
dev-db-stop:
	podman rm -f auditvision-pg

.PHONY: help
help:
	@grep -E '^[a-zA-Z_-]+:.*?## .*$$' $(MAKEFILE_LIST) | awk 'BEGIN {FS = ":.*?## "}; {printf "\033[36m%-20s\033[0m %s\n", $$1, $$2}'
