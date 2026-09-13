-- Phase 2B-5: additive-only column for the new embedded TerraformPlanEvidence record, serialized as
-- JSON exactly like V2/V3's terraform_*_evidence columns. Nullable, and untouched for every
-- pre-2B-5 operation - the V1/V2/V3 schema/columns are unchanged.
ALTER TABLE runner_requests ADD COLUMN terraform_plan_evidence VARCHAR;
