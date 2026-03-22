from __future__ import annotations

from infrastructure.db.connection import get_conn, put_conn

SCHEMA_SQL = """
CREATE TABLE IF NOT EXISTS operators (
    operator_id          TEXT PRIMARY KEY,
    email                TEXT UNIQUE NOT NULL,
    password_hash        TEXT NOT NULL,
    created_at_unix_ms   BIGINT NOT NULL DEFAULT 0,
    status               TEXT NOT NULL DEFAULT 'ACTIVE',
    role                 TEXT NOT NULL DEFAULT 'OWNER'
);

CREATE TABLE IF NOT EXISTS operator_tenant_links (
    operator_id   TEXT NOT NULL,
    tenant_id     TEXT NOT NULL,
    PRIMARY KEY (operator_id, tenant_id)
);

CREATE TABLE IF NOT EXISTS operator_sessions (
    token               TEXT PRIMARY KEY,
    operator_id         TEXT NOT NULL REFERENCES operators(operator_id) ON DELETE CASCADE,
    issued_at_unix_ms   BIGINT NOT NULL,
    expires_at_unix_ms  BIGINT NOT NULL,
    client_ip           TEXT,
    user_agent          TEXT
);

CREATE TABLE IF NOT EXISTS tenant_identities (
    tenant_id       TEXT PRIMARY KEY,
    password_hash   TEXT NOT NULL
);

CREATE TABLE IF NOT EXISTS tenants (
    tenant_id   TEXT PRIMARY KEY,
    created_at  TIMESTAMPTZ NOT NULL DEFAULT now()
);

CREATE TABLE IF NOT EXISTS tenant_configs (
    tenant_id   TEXT PRIMARY KEY REFERENCES tenants(tenant_id) ON DELETE CASCADE,
    config      JSONB NOT NULL DEFAULT '{}',
    updated_at  TIMESTAMPTZ NOT NULL DEFAULT now()
);

CREATE TABLE IF NOT EXISTS seed_endpoints (
    tenant_id   TEXT NOT NULL REFERENCES tenants(tenant_id) ON DELETE CASCADE,
    endpoint    TEXT NOT NULL,
    PRIMARY KEY (tenant_id, endpoint)
);

CREATE TABLE IF NOT EXISTS snapshots (
    tenant_id   TEXT NOT NULL,
    cycle_id    TEXT NOT NULL,
    payload     JSONB NOT NULL,
    created_at  TIMESTAMPTZ NOT NULL DEFAULT now(),
    PRIMARY KEY (tenant_id, cycle_id)
);

CREATE TABLE IF NOT EXISTS temporal_states (
    tenant_id   TEXT NOT NULL,
    cycle_id    TEXT NOT NULL,
    payload     JSONB NOT NULL,
    updated_at  TIMESTAMPTZ NOT NULL DEFAULT now(),
    PRIMARY KEY (tenant_id, cycle_id)
);

CREATE TABLE IF NOT EXISTS layer0_baselines (
    tenant_id   TEXT PRIMARY KEY,
    payload     JSONB NOT NULL,
    updated_at  TIMESTAMPTZ NOT NULL DEFAULT now()
);

CREATE TABLE IF NOT EXISTS layer3_snapshots (
    tenant_id   TEXT NOT NULL,
    cycle_id    TEXT NOT NULL,
    payload     JSONB NOT NULL,
    updated_at  TIMESTAMPTZ NOT NULL DEFAULT now(),
    PRIMARY KEY (tenant_id, cycle_id)
);

CREATE TABLE IF NOT EXISTS trust_graph_snapshots (
    tenant_id    TEXT NOT NULL,
    snapshot_id  TEXT NOT NULL,
    cycle_id     TEXT,
    payload      JSONB NOT NULL,
    created_at   TIMESTAMPTZ NOT NULL DEFAULT now(),
    PRIMARY KEY (tenant_id, snapshot_id)
);

CREATE TABLE IF NOT EXISTS cycle_metadata (
    id                  BIGSERIAL PRIMARY KEY,
    tenant_id           TEXT NOT NULL,
    cycle_id            TEXT,
    cycle_number        BIGINT,
    status              TEXT,
    schema_version      TEXT,
    timestamp_unix_ms   BIGINT,
    payload             JSONB NOT NULL
);

CREATE INDEX IF NOT EXISTS idx_cycle_metadata_tenant ON cycle_metadata(tenant_id);
CREATE INDEX IF NOT EXISTS idx_cycle_metadata_cycle  ON cycle_metadata(tenant_id, cycle_id);

CREATE TABLE IF NOT EXISTS telemetry (
    id           BIGSERIAL PRIMARY KEY,
    tenant_id    TEXT NOT NULL,
    cycle_id     TEXT NOT NULL,
    sequence     INT,
    record_type  TEXT,
    timestamp_ms BIGINT,
    payload      JSONB NOT NULL
);

CREATE INDEX IF NOT EXISTS idx_telemetry_tenant_cycle ON telemetry(tenant_id, cycle_id);

CREATE TABLE IF NOT EXISTS guardian_records (
    id          BIGSERIAL PRIMARY KEY,
    tenant_id   TEXT NOT NULL,
    cycle_id    TEXT,
    payload     JSONB NOT NULL,
    created_at  TIMESTAMPTZ NOT NULL DEFAULT now()
);

CREATE INDEX IF NOT EXISTS idx_guardian_records_tenant       ON guardian_records(tenant_id);
CREATE INDEX IF NOT EXISTS idx_guardian_records_tenant_cycle ON guardian_records(tenant_id, cycle_id);

CREATE TABLE IF NOT EXISTS cycle_locks (
    tenant_id           TEXT PRIMARY KEY REFERENCES tenants(tenant_id) ON DELETE CASCADE,
    cycle_id            TEXT NOT NULL,
    cycle_number        BIGINT,
    started_at_unix_ms  BIGINT,
    updated_at_unix_ms  BIGINT,
    stage               TEXT,
    pid                 INT,
    hostname            TEXT,
    status              TEXT NOT NULL DEFAULT 'active'
);

CREATE TABLE IF NOT EXISTS scheduler_states (
    tenant_id   TEXT PRIMARY KEY,
    payload     JSONB NOT NULL,
    updated_at  TIMESTAMPTZ NOT NULL DEFAULT now()
);

CREATE TABLE IF NOT EXISTS fingerprints (
    tenant_id   TEXT NOT NULL,
    entity_id   TEXT NOT NULL,
    payload     JSONB NOT NULL,
    updated_at  TIMESTAMPTZ NOT NULL DEFAULT now(),
    PRIMARY KEY (tenant_id, entity_id)
);
"""


def ensure_schema() -> None:
    conn = get_conn()
    try:
        with conn.cursor() as cur:
            cur.execute(SCHEMA_SQL)
        conn.commit()
    finally:
        put_conn(conn)
