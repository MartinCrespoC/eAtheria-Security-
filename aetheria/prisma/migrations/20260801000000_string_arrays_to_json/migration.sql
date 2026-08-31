-- Convert PostgreSQL-only scalar list columns to JSONB so the schema is
-- portable to MySQL / MariaDB / SQLite. Existing array values are preserved
-- via to_jsonb().
-- AlterTable: api_keys.scopes text[] -> jsonb
ALTER TABLE "api_keys"
ALTER COLUMN "scopes" DROP DEFAULT,
  ALTER COLUMN "scopes" TYPE JSONB USING to_jsonb("scopes"),
  ALTER COLUMN "scopes"
SET DEFAULT '["analysis:create", "analysis:read"]'::jsonb;
-- AlterTable: iac_rules."fileTypes" text[] -> jsonb
ALTER TABLE "iac_rules"
ALTER COLUMN "fileTypes" DROP DEFAULT,
  ALTER COLUMN "fileTypes" TYPE JSONB USING to_jsonb("fileTypes"),
  ALTER COLUMN "fileTypes"
SET DEFAULT '[]'::jsonb;
-- AlterTable: custom_scan_rules.languages text[] -> jsonb
ALTER TABLE "custom_scan_rules"
ALTER COLUMN "languages" DROP DEFAULT,
  ALTER COLUMN "languages" TYPE JSONB USING to_jsonb("languages"),
  ALTER COLUMN "languages"
SET DEFAULT '[]'::jsonb;
