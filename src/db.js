'use strict';
const path = require('path');
const fs = require('fs');
const { DatabaseSync } = require('node:sqlite');

const DATA_DIR = path.join(__dirname, '..', 'data');
if (!fs.existsSync(DATA_DIR)) fs.mkdirSync(DATA_DIR, { recursive: true });

const db = new DatabaseSync(path.join(DATA_DIR, 'access.db'));

db.exec(`
  PRAGMA journal_mode = WAL;

  CREATE TABLE IF NOT EXISTS employees (
    id            INTEGER PRIMARY KEY AUTOINCREMENT,
    name          TEXT NOT NULL,
    email         TEXT NOT NULL UNIQUE,
    password_hash TEXT NOT NULL,
    department    TEXT NOT NULL DEFAULT '',
    role          TEXT NOT NULL DEFAULT 'employee' CHECK (role IN ('employee','admin')),
    active        INTEGER NOT NULL DEFAULT 1,
    created_at    TEXT NOT NULL DEFAULT (datetime('now'))
  );

  CREATE TABLE IF NOT EXISTS visitors (
    id              INTEGER PRIMARY KEY AUTOINCREMENT,
    name            TEXT NOT NULL,
    document_type   TEXT NOT NULL,
    document_number TEXT NOT NULL,
    company         TEXT NOT NULL DEFAULT '',
    host_id         INTEGER NOT NULL REFERENCES employees(id),
    created_at      TEXT NOT NULL DEFAULT (datetime('now'))
  );

  CREATE TABLE IF NOT EXISTS passes (
    id          INTEGER PRIMARY KEY AUTOINCREMENT,
    code        TEXT NOT NULL UNIQUE,          -- identificador opaco (UUID) do passe
    type        TEXT NOT NULL CHECK (type IN ('employee','visitor')),
    employee_id INTEGER REFERENCES employees(id),
    visitor_id  INTEGER REFERENCES visitors(id),
    purpose     TEXT NOT NULL DEFAULT '',
    valid_from  TEXT NOT NULL,
    valid_until TEXT NOT NULL,
    status      TEXT NOT NULL DEFAULT 'active' CHECK (status IN ('active','revoked')),
    created_at  TEXT NOT NULL DEFAULT (datetime('now'))
  );

  CREATE TABLE IF NOT EXISTS access_logs (
    id         INTEGER PRIMARY KEY AUTOINCREMENT,
    pass_id    INTEGER REFERENCES passes(id),
    direction  TEXT NOT NULL CHECK (direction IN ('in','out')),
    result     TEXT NOT NULL CHECK (result IN ('granted','denied')),
    reason     TEXT NOT NULL DEFAULT '',
    gate       TEXT NOT NULL DEFAULT 'Portaria Principal',
    created_at TEXT NOT NULL DEFAULT (datetime('now','localtime'))
  );

  CREATE INDEX IF NOT EXISTS idx_passes_code   ON passes(code);
  CREATE INDEX IF NOT EXISTS idx_logs_created  ON access_logs(created_at);
`);

// Migração: fotografia do documento do visitante (digitalizada no totem)
const visitorCols = db.prepare(`PRAGMA table_info(visitors)`).all().map(c => c.name);
if (!visitorCols.includes('document_image')) {
  db.exec(`ALTER TABLE visitors ADD COLUMN document_image TEXT`);
}

module.exports = db;
