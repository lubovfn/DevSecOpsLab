# 🐳 Container Security Lab

Полный гид по атакам и защите Docker и Kubernetes.
---

## Содержание
1. Введение в контейнеризацию
2. Основные техники побега
3. Лабораторные атаки (Docker + kind)
4. Лучшие практики защиты
5. Инструменты мониторинга (Falco, NeuVector)
6. Seccomp и Audit Logs
7. Threat Modeling (STRIDE)

---

## Подготовка окружения

### Установка kind
```bash
curl -Lo ./kind https://kind.sigs.k8s.io/dl/v0.22.0/kind-linux-amd64
chmod +x ./kind && mv ./kind /usr/local/bin/
kind create cluster --name sec-lab
```

### Проверка
```bash
kubectl cluster-info --context kind-sec-lab
```

---

##  Лабораторные атаки

### Атака 1. Побег через Docker socket
```bash
docker run -v /var/run/docker.sock:/var/run/docker.sock -it alpine sh
apk add docker-cli
docker run --privileged -v /:/host alpine chroot /host sh
```

---

### Атака 2. Привилегированный под
Файл: `manifests/bad-pod.yaml`
```yaml
apiVersion: v1
kind: Pod
metadata:
  name: bad-pod
spec:
  containers:
  - name: attacker
    image: alpine
    command: ["sh", "-c", "sleep infinity"]
    securityContext:
      privileged: true
```

---

###  Атака 3. Уязвимый образ
Файл: `manifests/vuln-pod.yaml`
```yaml
apiVersion: v1
kind: Pod
metadata:
  name: vuln-pod
spec:
  containers:
  - name: web
    image: alpine:3.10
    command: ["sh", "-c", "sleep infinity"]
```

---

###  Атака 4. RBAC-эскалация
```bash
kubectl run attacker --rm -it --image=bitnami/kubectl
kubectl get secrets --all-namespaces
```

---

## Лучшие практики защиты

- Минимальные привилегии (`--cap-drop ALL`, `runAsNonRoot: true`)  
- Доверенные образы (`DOCKER_CONTENT_TRUST=1`, Trivy scan)  
- Seccomp профили (`manifests/seccomp/`)  
- Falco правила (docker.sock access, RBAC escalation)  
- NeuVector для сетевой защиты и image scanning  
- Audit Logs в Kubernetes  

---

##  Threat Modeling (STRIDE)

| Asset              | Threat                                   | Mitigation                           |
|--------------------|------------------------------------------|--------------------------------------|
| Docker socket      | Побег на хост                            | Не монтировать сокет, Falco правило  |
| Kubernetes API     | Захват ServiceAccount с правами admin    | RBAC least privilege, Falco audit    |
| Контейнерные образы| Supply-chain атаки, CVE                  | DOCKER_CONTENT_TRUST, Trivy, NeuVector|
| Runtime (runc)     | Уязвимости ядра и контейнерного рантайма | Обновления, seccomp, Audit Logs      |

---

##  Заключение
Эта лаборатория показывает, как атакующие могут сбежать из контейнера и как защитить кластер.  
Комбинация **минимальных привилегий, доверенных образов, Falco, NeuVector, Seccomp и Audit Logs** позволяет построить защищённый DevSecOps-процесс.


---

## Дополнительно: Falco правила и Audit Policy

- Falco custom rules: `manifests/falco/rules.d/custom-rules.yaml`  
  Применение (Helm/Falco values):
  ```bash
  # Пример копирования правил в DaemonSet через ConfigMap
  kubectl -n falco create configmap falco-custom-rules --from-file=manifests/falco/rules.d/custom-rules.yaml
  kubectl -n falco patch daemonset falco --type='json' -p='[
    {"op":"add","path":"/spec/template/spec/volumes/-","value":{"name":"falco-custom","configMap":{"name":"falco-custom-rules"}}},
    {"op":"add","path":"/spec/template/spec/containers/0/volumeMounts/-","value":{"name":"falco-custom","mountPath":"/etc/falco/rules.d/custom-rules.yaml","subPath":"custom-rules.yaml"}}
  ]'
  ```

- Kubernetes Audit Policy: `manifests/audit/audit-policy.yaml`  
  Включение (пример флагов kube-apiserver):
  ```
  --audit-log-path=/var/log/kubernetes/audit.log
  --audit-policy-file=/etc/kubernetes/audit/audit-policy.yaml
  --audit-log-maxage=10
  --audit-log-maxbackup=5
  --audit-log-maxsize=100
  ```


---

## Применение: Falco ConfigMap + patch DaemonSet, kube-apiserver Audit Flags, Kyverno и Pod Security Admission

### 1) Falco: добавляем кастомные правила через ConfigMap и patch DaemonSet
```bash
# Создаём ConfigMap с нашими правилами
kubectl -n falco create configmap falco-custom-rules --from-file=manifests/falco/rules.d/custom-rules.yaml

# Монтируем ConfigMap в DaemonSet Falco (rules.d/custom-rules.yaml)
kubectl -n falco patch daemonset falco --type='json' -p='[
  {"op":"add","path":"/spec/template/spec/volumes/-","value":{"name":"falco-custom","configMap":{"name":"falco-custom-rules"}}},
  {"op":"add","path":"/spec/template/spec/containers/0/volumeMounts/-","value":{"name":"falco-custom","mountPath":"/etc/falco/rules.d/custom-rules.yaml","subPath":"custom-rules.yaml"}}
]'
```

### 2) kube-apiserver: включаем Audit Logs (пример для kind)
> В kind контроль-плейн — это Docker-контейнер `kind-control-plane`. Меняем файл манифеста kube-apiserver внутри контейнера и добавляем флаги аудита.

```bash
# Заходим в контейнер control-plane
docker exec -it kind-sec-lab-control-plane bash

# Редактируем манифест kube-apiserver
vi /etc/kubernetes/manifests/kube-apiserver.yaml

# Добавляем флаги:
# - --audit-log-path=/var/log/kubernetes/audit.log
# - --audit-policy-file=/etc/kubernetes/audit/audit-policy.yaml
# - --audit-log-maxage=10
# - --audit-log-maxbackup=5
# - --audit-log-maxsize=100
#
# И добавляем volumeMounts/volumes для файлов политики/логов (hostPath)
# Пример готовой политики в: manifests/audit/audit-policy.yaml

# Создаём директории и копируем policy внутрь узла
mkdir -p /etc/kubernetes/audit /var/log/kubernetes
cat >/etc/kubernetes/audit/audit-policy.yaml <<'EOF'
$(cat manifests/audit/audit-policy.yaml)
EOF

# kubelet перезапустит kube-apiserver автоматически (static pod). Проверяем логи:
exit
kubectl -n kube-system describe pod -l component=kube-apiserver
```

### 3) Kyverno: установка и включение запретов (privileged + docker.sock)
```bash
# Установка Kyverno (Helm)
helm repo add kyverno https://kyverno.github.io/kyverno/
helm repo update
helm install kyverno kyverno/kyverno -n kyverno --create-namespace

# Применение ClusterPolicy
kubectl apply -f manifests/kyverno/clusterpolicy-disallow-privileged-and-docker-sock.yaml
```

Проверка: попытка применить `manifests/bad-pod.yaml` или под с volumeMount `/var/run/docker.sock` должна быть **заблокирована**.

### 4) Pod Security Admission (PSA): включаем профиль restricted через метки namespace
```bash
# Создаём пространство имён с профилями PSA
kubectl apply -f manifests/psa/namespace-restricted.yaml

# Пробуем задеплоить привилегированный Pod в restricted-ns
kubectl apply -f manifests/psa/bad-pod-psa.yaml
# Ожидаем отказ с сообщением о нарушении PSA "restricted"
```

> **PSA vs Kyverno**: PSA — встроенный базовый контроль для Pod Security уровней. Kyverno — гибкая политика для детальных правил (docker.sock, специфичные контексты, исключения и т.п.). Они дополняют друг друга.


---

## Применение дополнительных политик безопасности

###  Falco custom rules
Файл: `manifests/falco/rules.d/custom-rules.yaml`

Применение:
```bash
kubectl -n falco create configmap falco-custom-rules --from-file=manifests/falco/rules.d/custom-rules.yaml

kubectl -n falco patch daemonset falco --type='json' -p='[
  {"op":"add","path":"/spec/template/spec/volumes/-","value":{"name":"falco-custom","configMap":{"name":"falco-custom-rules"}}},
  {"op":"add","path":"/spec/template/spec/containers/0/volumeMounts/-","value":{"name":"falco-custom","mountPath":"/etc/falco/rules.d/custom-rules.yaml","subPath":"custom-rules.yaml"}}
]'
```

###  Kubernetes Audit Policy
Файл: `manifests/audit/audit-policy.yaml`

Флаги для kube-apiserver:
```
--audit-log-path=/var/log/kubernetes/audit.log
--audit-policy-file=/etc/kubernetes/audit/audit-policy.yaml
--audit-log-maxage=10
--audit-log-maxbackup=5
--audit-log-maxsize=100
```

###  Kyverno Policy
Файл: `manifests/kyverno/restrict-privileged-dockersock.yaml`

Политика запрещает:
- Запуск контейнеров с `privileged: true`
- Монтирование `/var/run/docker.sock`

Применение:
```bash
kubectl apply -f manifests/kyverno/restrict-privileged-dockersock.yaml
```

###  Pod Security Admission (restricted)
Файл: `manifests/pod-security/restricted-namespace.yaml`

Создание namespace с политикой PSA:
```bash
kubectl apply -f manifests/pod-security/restricted-namespace.yaml
```

Любые поды, нарушающие профиль `restricted`, будут отклонены при деплое в этот namespace.


---

## NetworkPolicy: изоляция pod-подключений

Включаем zero-trust модель внутри кластера.

Файл: `manifests/networkpolicy/networkpolicy-deny-all-allow-namespace.yaml`

```yaml
apiVersion: networking.k8s.io/v1
kind: NetworkPolicy
metadata:
  name: deny-all
  namespace: restricted-ns
spec:
  podSelector: {}
  policyTypes:
  - Ingress
  - Egress
---
apiVersion: networking.k8s.io/v1
kind: NetworkPolicy
metadata:
  name: allow-namespace
  namespace: restricted-ns
spec:
  podSelector: {}
  policyTypes:
  - Ingress
  ingress:
  - from:
    - podSelector: {}
```

- Первый policy полностью блокирует ingress/egress.  
- Второй разрешает общение только между pod’ами в пределах namespace.  

Применение:
```bash
kubectl apply -f manifests/networkpolicy/networkpolicy-deny-all-allow-namespace.yaml
```

---

##  Trivy Pipeline для GitHub Actions

Файл: `pipelines/trivy-scan.yml`

```yaml
name: Trivy Image Scan

on:
  push:
    branches:
      - main
  pull_request:

jobs:
  trivy:
    runs-on: ubuntu-latest
    steps:
      - name: Checkout repository
        uses: actions/checkout@v3

      - name: Set up Docker Buildx
        uses: docker/setup-buildx-action@v2

      - name: Build Docker image
        run: |
          docker build -t myapp:${{ github.sha }} .

      - name: Run Trivy vulnerability scanner
        uses: aquasecurity/trivy-action@master
        with:
          image-ref: myapp:${{ github.sha }}
          format: 'table'
          exit-code: '1'
          ignore-unfixed: true
          vuln-type: 'os,library'
          severity: 'CRITICAL,HIGH'
```

pipeline автоматически сканирует Docker-образы при каждом push/PR.  
Если найдутся критические уязвимости  билд завершится с ошибкой.  


---

##  NetworkPolicy: изоляция pod-подключений

> Требуется CNI с поддержкой NetworkPolicy (Calico/Cilium). В kind без такого CNI политики не применяются.

Файлы:
- `manifests/networkpolicy/ns-lab.yaml`
- `manifests/networkpolicy/np-default-deny-all.yaml`
- `manifests/networkpolicy/np-allow-dns-egress.yaml`
- `manifests/networkpolicy/np-allow-same-app.yaml`
- `manifests/networkpolicy/np-allow-web-to-db.yaml`
- Тестовые приложения: `manifests/apps/web.yaml`, `manifests/apps/db.yaml`

Быстрый старт:
```bash
kubectl apply -f manifests/networkpolicy/ns-lab.yaml
kubectl apply -f manifests/apps/web.yaml
kubectl apply -f manifests/apps/db.yaml
kubectl apply -f manifests/networkpolicy/np-default-deny-all.yaml
kubectl apply -f manifests/networkpolicy/np-allow-dns-egress.yaml
kubectl apply -f manifests/networkpolicy/np-allow-web-to-db.yaml
kubectl apply -f manifests/networkpolicy/np-allow-same-app.yaml
```

Проверка (в ns lab):
```bash
kubectl -n lab run curl --image=curlimages/curl -it --rm -- /bin/sh
# Ожидаем блокировку всего по умолчанию...
curl -sS web:80 || echo "blocked"
curl -sS db:5432 || echo "blocked"
# Метка app=web даёт доступ к db:5432
kubectl -n lab run web-test --image=curlimages/curl -l app=web -it --rm -- sh -lc 'nc -vz db 5432 || true'
# DNS должен работать
nslookup kubernetes.default.svc.cluster.local || true
```

---

##  Trivy: локальный запуск и CI-пайплайн

Локально:
```bash
scripts/trivy-scan.sh
```

CI (GitHub Actions):
- workflow: `.github/workflows/trivy.yml`
  - собирает `Dockerfile.vuln`
  - сканирует образ (фейлит PR при HIGH/CRITICAL)
  - дополнительно сканирует файловую систему (манифесты, Dockerfile)

Игнор-лист:
- `.trivyignore` — пример исключений CVE.
