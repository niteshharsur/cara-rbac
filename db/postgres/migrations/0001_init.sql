-- 0001_init.sql
-- CARA-RBAC PostgreSQL Schema
-- Run via: golang-migrate up

CREATE EXTENSION IF NOT EXISTS "pgcrypto";

CREATE TABLE applications (
    id              UUID PRIMARY KEY DEFAULT gen_random_uuid(),
    name            TEXT NOT NULL,
    source_repo_url TEXT,
    artifact_hub_id TEXT,
    created_at      TIMESTAMPTZ NOT NULL DEFAULT now()
);

CREATE TABLE clusters (
    id                    UUID PRIMARY KEY DEFAULT gen_random_uuid(),
    name                  TEXT NOT NULL,
    api_server_url        TEXT NOT NULL,
    kubeconfig_secret_ref TEXT NOT NULL,
    k8s_version           TEXT,
    created_at            TIMESTAMPTZ NOT NULL DEFAULT now()
);

CREATE TABLE scans (
    id                     UUID PRIMARY KEY DEFAULT gen_random_uuid(),
    application_id         UUID NOT NULL REFERENCES applications(id),
    cluster_id             UUID REFERENCES clusters(id),
    mode                   TEXT NOT NULL CHECK (mode IN ('pre_deployment','hybrid','runtime_only')),
    status                 TEXT NOT NULL DEFAULT 'pending'
                              CHECK (status IN ('pending','running','completed','failed')),
    runtime_window_seconds INT DEFAULT 604800,
    started_at             TIMESTAMPTZ,
    completed_at           TIMESTAMPTZ,
    created_at             TIMESTAMPTZ NOT NULL DEFAULT now()
);

CREATE TABLE pods (
    id               UUID PRIMARY KEY DEFAULT gen_random_uuid(),
    scan_id          UUID NOT NULL REFERENCES scans(id) ON DELETE CASCADE,
    pod_name         TEXT NOT NULL,
    namespace        TEXT NOT NULL,
    service_account  TEXT NOT NULL,
    main_executable  TEXT,
    entry_point_file TEXT,
    UNIQUE (scan_id, pod_name, namespace)
);

CREATE TABLE permission_observations (
    id                BIGSERIAL PRIMARY KEY,
    scan_id           UUID NOT NULL REFERENCES scans(id) ON DELETE CASCADE,
    pod_id            UUID REFERENCES pods(id) ON DELETE CASCADE,
    source            TEXT NOT NULL CHECK (source IN ('requested','static','runtime','cluster')),
    verb              TEXT NOT NULL,
    resource          TEXT NOT NULL,
    api_group         TEXT NOT NULL DEFAULT '',
    scope             TEXT NOT NULL CHECK (scope IN ('cluster','namespace','resource-specific')),
    resource_names    TEXT[],
    first_observed_at TIMESTAMPTZ,
    last_observed_at  TIMESTAMPTZ,
    observed_count    INT DEFAULT 0,
    is_startup_only   BOOLEAN DEFAULT FALSE,
    source_role       TEXT,
    source_binding    TEXT,
    call_site_file    TEXT,
    call_site_line    INT
);

CREATE INDEX idx_perm_obs_lookup ON permission_observations (scan_id, pod_id, source, verb, resource);
CREATE INDEX idx_perm_obs_runtime_startup ON permission_observations (scan_id)
    WHERE source='runtime' AND is_startup_only = TRUE;

CREATE TABLE classifications (
    id              BIGSERIAL PRIMARY KEY,
    scan_id         UUID NOT NULL REFERENCES scans(id) ON DELETE CASCADE,
    pod_id          UUID NOT NULL REFERENCES pods(id) ON DELETE CASCADE,
    verb            TEXT NOT NULL,
    resource        TEXT NOT NULL,
    scope           TEXT NOT NULL,
    class           TEXT NOT NULL CHECK (class IN ('CEP','SFP','DP','SOP','DRP','RP')),
    confidence      NUMERIC(4,3),
    confidence_band TEXT CHECK (confidence_band IN ('HIGH','MEDIUM','LOW')),
    threat_score    NUMERIC(4,3),
    rationale       TEXT,
    evidence_ref    JSONB,
    created_at      TIMESTAMPTZ NOT NULL DEFAULT now()
);

CREATE INDEX idx_classifications_scan_class ON classifications (scan_id, class);

CREATE TABLE minimization_results (
    id                UUID PRIMARY KEY DEFAULT gen_random_uuid(),
    scan_id           UUID NOT NULL REFERENCES scans(id) ON DELETE CASCADE,
    pod_id            UUID NOT NULL REFERENCES pods(id) ON DELETE CASCADE,
    original_count    INT NOT NULL,
    minimized_count   INT NOT NULL,
    reduction_pct     NUMERIC(5,2),
    minimized_yaml    TEXT NOT NULL,
    rollback_script   TEXT NOT NULL,
    validation_status TEXT CHECK (validation_status IN ('passed','failed','skipped')),
    created_at        TIMESTAMPTZ NOT NULL DEFAULT now()
);

CREATE TABLE attack_paths (
    id         BIGSERIAL PRIMARY KEY,
    scan_id    UUID NOT NULL REFERENCES scans(id) ON DELETE CASCADE,
    pod_id     UUID NOT NULL REFERENCES pods(id) ON DELETE CASCADE,
    target     TEXT NOT NULL,
    impact     TEXT NOT NULL,
    severity   NUMERIC(4,3),
    path_json  JSONB NOT NULL,
    created_at TIMESTAMPTZ NOT NULL DEFAULT now()
);

CREATE TABLE users (
    id            UUID PRIMARY KEY DEFAULT gen_random_uuid(),
    email         TEXT UNIQUE NOT NULL,
    password_hash TEXT,
    role          TEXT NOT NULL DEFAULT 'viewer' CHECK (role IN ('admin','engineer','viewer')),
    created_at    TIMESTAMPTZ NOT NULL DEFAULT now()
);

CREATE TABLE audit_trail (
    id          BIGSERIAL PRIMARY KEY,
    user_id     UUID REFERENCES users(id),
    action      TEXT NOT NULL,
    target_type TEXT NOT NULL,
    target_id   UUID,
    metadata    JSONB,
    created_at  TIMESTAMPTZ NOT NULL DEFAULT now()
);
