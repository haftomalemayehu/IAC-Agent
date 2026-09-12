-- Phase 2B-4: additive-only columns for the three new embedded evidence records, each serialized
-- as JSON exactly like V2's terraform_process_evidence column. Nullable, and untouched for every
-- pre-2B-4 operation - the V1/V2 schema/columns are unchanged.
ALTER TABLE runner_requests ADD COLUMN terraform_init_evidence VARCHAR;
ALTER TABLE runner_requests ADD COLUMN terraform_validate_evidence VARCHAR;
ALTER TABLE runner_requests ADD COLUMN terraform_provider_schema_evidence VARCHAR;
