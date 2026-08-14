-- Synthetic "production" data only. No real people, credentials, or secrets.

CREATE TABLE customers (
    id SERIAL PRIMARY KEY,
    name TEXT NOT NULL,
    email TEXT NOT NULL
);

INSERT INTO customers (name, email) VALUES
    ('Alice Example', 'alice@example.invalid'),
    ('Bob Example', 'bob@example.invalid'),
    ('Carol Example', 'carol@example.invalid');

CREATE TABLE internal_secrets (
    id SERIAL PRIMARY KEY,
    label TEXT NOT NULL,
    value TEXT NOT NULL
);

INSERT INTO internal_secrets (label, value) VALUES
    ('synthetic-api-token', 'not-a-real-secret-0000'),
    ('synthetic-db-password', 'synthetic-only');

CREATE TABLE audit_log (
    id SERIAL PRIMARY KEY,
    at TIMESTAMPTZ NOT NULL DEFAULT NOW(),
    action TEXT NOT NULL
);

INSERT INTO audit_log (action) VALUES
    ('seeded synthetic production database');
