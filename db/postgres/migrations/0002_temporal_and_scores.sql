-- 0002_temporal_and_scores.sql
-- Add temporal analytics, risk scoring, and deployment validation support to CARA-RBAC tables

-- Scans updates
ALTER TABLE scans ADD COLUMN IF NOT EXISTS app_risk_score NUMERIC(5,2) DEFAULT 0.0;
ALTER TABLE scans ADD COLUMN IF NOT EXISTS risk_explanation TEXT;

-- Pods updates
ALTER TABLE pods ADD COLUMN IF NOT EXISTS pod_risk_score NUMERIC(5,2) DEFAULT 0.0;

-- Observations updates (temporal stats)
ALTER TABLE permission_observations ADD COLUMN IF NOT EXISTS execution_frequency NUMERIC(8,2) DEFAULT 0.0; -- calls per day
ALTER TABLE permission_observations ADD COLUMN IF NOT EXISTS first_seen TIMESTAMPTZ;
ALTER TABLE permission_observations ADD COLUMN IF NOT EXISTS last_seen TIMESTAMPTZ;

-- Classifications updates
ALTER TABLE classifications ADD COLUMN IF NOT EXISTS confidence_score NUMERIC(4,3) DEFAULT 0.0;

-- Minimization updates
ALTER TABLE minimization_results ADD COLUMN IF NOT EXISTS role_splitting_suggestions JSONB;
ALTER TABLE minimization_results ADD COLUMN IF NOT EXISTS deployability_status TEXT DEFAULT 'skipped'; -- 'passed', 'failed', 'skipped'
ALTER TABLE minimization_results ADD COLUMN IF NOT EXISTS validation_details TEXT;
