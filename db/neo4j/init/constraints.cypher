// Neo4j initialization — constraints and indexes
CREATE CONSTRAINT pod_id_unique IF NOT EXISTS FOR (p:Pod) REQUIRE p.id IS UNIQUE;
CREATE CONSTRAINT resource_key_unique IF NOT EXISTS FOR (r:Resource) REQUIRE r.key IS UNIQUE;
CREATE CONSTRAINT sa_key_unique IF NOT EXISTS FOR (s:ServiceAccount) REQUIRE s.key IS UNIQUE;
CREATE INDEX scan_id_index IF NOT EXISTS FOR (p:Pod) ON (p.scanId);
