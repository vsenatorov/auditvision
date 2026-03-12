# audit-radar — k8s / k3s deploy

## Отличия от OpenShift

| Файл | Что изменено |
|------|-------------|
| 01-postgres.yaml | image: postgres:15 (вместо registry.redhat.io), mountPath: /var/lib/postgresql/data |
| 03-ui.yaml | Route → Ingress (Traefik, встроен в k3s), nip.io hostname |
| 08-ollama.yaml | убран storageClassName (k3s использует local-path) |
| 09,10,11 | без изменений |

## Деплой

```bash
kubectl apply -f 00-namespace.yaml
kubectl apply -f 01-postgres.yaml
kubectl apply -f 11-rbac.yaml
kubectl apply -f 03-ui.yaml
kubectl apply -f 02-collector.yaml
kubectl apply -f 08-ollama.yaml   # долго — качает granite3.2:2b (~1.5GB)
kubectl apply -f 09-analyzer.yaml
kubectl apply -f 10-alerter.yaml
```

## Проверка

```bash
kubectl get pods -n audit-vision
kubectl get ingress -n audit-vision
```

## UI доступен по адресу

http://audit.192.168.10.30.nip.io/ui

(nip.io резолвит автоматически — интернет не нужен для резолва)
