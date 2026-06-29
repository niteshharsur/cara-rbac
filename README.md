# CARA-RBAC
**Context-Aware Runtime-Assisted Excessive RBAC Permission Detection and Minimization Framework for Kubernetes**

## Phases
- **Phase A (M1–M3):** Pre-Deployment Static Analysis
- **Phase B (M4):** Cluster Context Collection
- **Phase C (M5–M7):** Runtime Monitoring, FP Reduction & Minimization

## Quick Start
\\\ash
docker-compose -f docker-compose.dev.yml up
\\\

## Modules
| Module | Service | Language | Purpose |
|--------|---------|----------|---------|
| M1 | rbac-analyzer | Go | YAML/Helm RBAC parsing ? P_req |
| M2 | pod-matcher | Python | LLM pod-program matching |
| M3 | behavior-analyzer | Python+CodeQL | RefGraph + reachability ? P_static |
| M4 | cluster-collector | Go | Live cluster RBAC + audit/eBPF ? P_cluster |
| M5 | runtime-monitor | Go | Stream correlation ? P_runtime |
| M6 | fp-engine | Python | 6-class false positive reduction |
| M7 | minimizer | Go | P_min ? minimized RBAC YAML |
