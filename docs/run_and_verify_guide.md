# CARA-RBAC Run and Verification Guide

This guide describes how to run the CARA-RBAC context-aware Kubernetes RBAC minimization stack, initialize databases, execute the modular pipeline phases, and verify the correctness of the system.

---

## 🏗️ Architecture & Component Flow

CARA-RBAC consists of **10 distinct components** (8 backend services, database migrations, and an infrastructure stack). The services communicate via PostgreSQL, Neo4j, Redis, and direct REST/WebSocket endpoints.

```mermaid
graph TD
    subgraph Infrastructure
        PG[(PostgreSQL)]
        N4J[(Neo4j Graph DB)]
        RD[(Redis Cache)]
        KF[(Kafka Events)]
    end

    subgraph Phase A - Pre-Deployment
        M1[rbac-analyzer] -->|P_req| PG
        M2[pod-matcher] -->|Resolve entrypoints| PG
        M3[behavior-analyzer] -->|P_static| PG
    end

    subgraph Phase B - Cluster Collection
        M4[cluster-collector] -->|P_cluster| PG
    end

    subgraph Phase C - Runtime & Minimization
        EA[eBPF Agent] -->|kernel events| M5[runtime-monitor]
        CC[Cluster Webhook] -->|audit events| M5
        M5 -->|P_runtime| PG
        M5 -->|Invalidate cache| RD
        M6[fp-engine] -->|Run partition rules| PG
        M7[minimizer] -->|Generate P_min| PG
        M7 -->|Apply to cluster| K8s[Kubernetes API]
    end

    subgraph Gateway & Frontend
        GW[api-gateway] -->|Query REST/GraphQL| PG
        GW -->|Proxy to| M7
        GW -->|Graph visualization| GS[graph-svc]
        GS -->|Sync & Query| N4J
        GS -->|Cross-reference| PG
    end
```

---

## ⚙️ Prerequisites

To run and verify the entire stack, ensure you have the following installed on your system:
- **Docker & Docker Compose**
- **Go 1.23+**
- **Python 3.12+**
- **PostgreSQL Client (`psql` or `golang-migrate`)**
- **kubectl & Helm** (if verifying cluster integrations or deploying Helm charts)

---

## 🚀 Step 1: Spin Up the Infrastructure

The infrastructure dependencies are defined in [docker-compose.dev.yml](file:///C:/Users/nites/OneDrive/Desktop/cara-rbac/docker-compose.dev.yml). This includes PostgreSQL, Neo4j, Redis, Kafka, and Zookeeper.

1. **Start the containers in the background:**
   ```bash
   docker-compose -f docker-compose.dev.yml up -d
   ```

2. **Verify that the containers are healthy:**
   ```bash
   docker-compose -f docker-compose.dev.yml ps
   ```

---

## 🗄️ Step 2: Initialize the PostgreSQL Database Schema

Apply the database migrations to set up tables, constraints, check expressions, and partition indexes.

### Option A: Using raw `psql` (Recommended for speed)
```bash
psql "postgresql://cara:cara_dev_secret@localhost:5432/cara_rbac?sslmode=disable" -f db/postgres/migrations/0001_init.sql
```

### Option B: Using `golang-migrate` CLI
```bash
migrate -path db/postgres/migrations -database "postgres://cara:cara_dev_secret@localhost:5432/cara_rbac?sslmode=disable" up
```

---

## 🧪 Step 3: Run the Services Locally

Copy `.env.example` to `.env` and fill in any secrets (e.g., your `OPENAI_API_KEY` for OpenAI-assisted image-to-entrypoint matching).
```bash
cp .env.example .env
```

### 1. Run the API Gateway (`api-gateway`)
The API Gateway is the central entry point for UI dashboards, REST requests, and GraphQL clients.
```bash
cd backend/api-gateway
# Install dependencies
go mod download
# Start the Gateway
go run cmd/serve/main.go
```
*Verification*: Open your browser and navigate to `http://localhost:8080/healthz`. You should receive `{"status":"ok", "service":"api-gateway"}`.

---

### 2. Phase A Verification: Pre-Deployment Parsing & Matchers

We will use the included [sample-app.yaml](file:///C:/Users/nites/OneDrive/Desktop/cara-rbac/backend/rbac-analyzer/testdata/sample-app.yaml) for verifying static analysis.

#### Run `rbac-analyzer` (M1)
This tool parses manifests, expands wildcard permissions, and records requested permissions ($P_{req}$).
```bash
cd backend/rbac-analyzer
go run cmd/analyzer/main.go --scan-id "11111111-1111-1111-1111-111111111111" --input "testdata/sample-app.yaml"
```
*Verification*: Query PostgreSQL table `permission_observations`. You should see records with `source = 'requested'`.

#### Run `pod-matcher` (M2)
Matches container images from the manifests to their source code repositories.
```bash
cd backend/pod-matcher
pip install -e .
python -m pod_matcher --scan-id "11111111-1111-1111-1111-111111111111" --source-dir "/path/to/my-app/src"
```
*Verification*: Check the `pods` table in PostgreSQL. The `entry_point_file` and `main_executable` columns should now be populated.

#### Run `behavior-analyzer` (M3)
Generates CodeQL database, maps API endpoints, and checks static reachability.
```bash
cd backend/behavior-analyzer
pip install -e .
python -m behavior_analyzer --scan-id "11111111-1111-1111-1111-111111111111" --source-dir "/path/to/my-app/src"
```
*Verification*: Check the `permission_observations` table in PostgreSQL. You should see records with `source = 'static'`.

---

### 3. Phase B Verification: Live Cluster Collection

#### Run `cluster-collector` (M4)
Pulls active ServiceAccount configurations and live role bindings.
```bash
cd backend/cluster-collector
go run cmd/collector/main.go --scan-id "11111111-1111-1111-1111-111111111111"
```
*Verification*: Check `permission_observations` table in PostgreSQL for records with `source = 'cluster'`.

---

### 4. Phase C Verification: Runtime Monitoring, Classifications, & Graph analysis

#### Run `runtime-monitor` (M5)
Maintains active HTTP endpoint for agents reporting actual API calls made.
```bash
cd backend/runtime-monitor
go run cmd/monitor/main.go --port 8081
```

##### Simulate a runtime event:
Send a synthetic k8s connect event to the monitor:
```bash
curl -X POST http://localhost:8081/api/v1/event -H "Content-Type: application/json" -d '{
  "scan_id": "11111111-1111-1111-1111-111111111111",
  "pod_name": "worker-79b8979fc-2tflm",
  "namespace": "sample-app",
  "verb": "get",
  "resource": "secrets",
  "is_startup": false
}'
```
*Verification*: Check the `permission_observations` table for `source = 'runtime'`.

#### Run the `fp-engine` (M6)
Runs the false-positive 6-class partitioning rules (CEP, SFP, DP, SOP, DRP, RP) and outputs classification tables.
```bash
cd backend/fp-engine
pip install -e .
python -m fp_engine --scan-id "11111111-1111-1111-1111-111111111111"
```
*Verification*: Verify `classifications` table in PostgreSQL is populated with threat scores, classifications, and rationales.

#### Run the Graph Service (`graph-svc`)
Syncs PostgreSQL records to Neo4j, maps nodes & edges, and calculates blast radius/attack paths.
```bash
cd backend/graph-svc
go run cmd/graph/main.go --port 8082
```
*Verification*: Run graph sync via curl:
```bash
curl -X POST http://localhost:8082/api/v1/scans/11111111-1111-1111-1111-111111111111/graph/sync
```

#### Run the `minimizer` (M7)
Creates minimized YAML roles and a rollback script.
```bash
cd backend/minimizer
go run cmd/minimizer/main.go --scan-id "11111111-1111-1111-1111-111111111111"
```
*Verification*: Verify `minimization_results` table in PostgreSQL has a minimized YAML payload and a rollback script.

---

## 🛠️ Step 4: Verification API Call Sheet (API Gateway Endpoints)

Once the backend services are running and populated, you can verify queries through the **API Gateway** (`localhost:8080`).

### 1. Register and Login to get Auth token
The API Gateway requires JWT authentication for protected routes.

#### Register a user:
```bash
curl -X POST http://localhost:8080/api/v1/auth/register \
  -H "Content-Type: application/json" \
  -d '{"email": "engineer@cara.dev", "password": "secure_dev_pass", "role": "engineer"}'
```

#### Login to get JWT Token:
```bash
curl -X POST http://localhost:8080/api/v1/auth/login \
  -H "Content-Type: application/json" \
  -d '{"email": "engineer@cara.dev", "password": "secure_dev_pass"}'
```
Response: `{"token": "<JWT_TOKEN>"}`. Copy `<JWT_TOKEN>` and use it in the headers for all subsequent calls: `-H "Authorization: Bearer <JWT_TOKEN>"`.

### 2. View Permission Summary
```bash
curl -X GET http://localhost:8080/api/v1/scans/11111111-1111-1111-1111-111111111111/permissions/summary \
  -H "Authorization: Bearer <JWT_TOKEN>"
```

### 3. Fetch Permission Graph (For D3.js visualization)
```bash
curl -X GET http://localhost:8080/api/v1/scans/11111111-1111-1111-1111-111111111111/graph/permissions \
  -H "Authorization: Bearer <JWT_TOKEN>"
```

### 4. Fetch Attack Paths
```bash
curl -X GET http://localhost:8080/api/v1/scans/11111111-1111-1111-1111-111111111111/graph/attack-paths \
  -H "Authorization: Bearer <JWT_TOKEN>"
```

### 5. Fetch Minimization Results (YAML & Rollback)
```bash
curl -X GET http://localhost:8080/api/v1/scans/11111111-1111-1111-1111-111111111111/minimization \
  -H "Authorization: Bearer <JWT_TOKEN>"
```
