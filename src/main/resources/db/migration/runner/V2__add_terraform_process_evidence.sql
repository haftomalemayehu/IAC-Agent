-- Phase 2B-3: additive-only column for the embedded TerraformProcessEvidence, serialized as JSON.
-- Nullable, and untouched for every pre-2B-3 operation - the V1 schema/columns are unchanged.
ALTER TABLE runner_requests ADD COLUMN terraform_process_evidence VARCHAR;
