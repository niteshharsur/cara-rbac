# ADR-001: Monorepo vs Polyrepo

**Status:** Accepted

## Context
All 7 CARA-RBAC modules share data contracts that change in lockstep during early development.

## Decision
Use a monorepo for the MVP. Split to polyrepo post-MVP if team size demands it.

## Consequences
- Easier atomic cross-module refactors
- Single CI pipeline can validate contracts end-to-end
