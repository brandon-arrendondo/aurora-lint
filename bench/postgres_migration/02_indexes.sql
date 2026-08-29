-- Apply after 03_load.sh finishes (plan §4 step 4) -- building these against
-- an empty table then loading is far cheaper than loading into an indexed one.

CREATE INDEX idx_violations_cwe_scan ON violations(cwe_scan_id);
CREATE INDEX idx_violations_rule ON violations(rule_id);
CREATE INDEX idx_violations_class ON violations(classification);
CREATE INDEX idx_cwe_scans_run ON cwe_scans(run_id);
CREATE INDEX idx_cwe_scans_cwe ON cwe_scans(cwe_id);
CREATE INDEX idx_runs_status ON runs(status);
CREATE INDEX idx_rw_results_run ON realworld_results(run_id);
CREATE INDEX idx_rw_results_project ON realworld_results(project);
CREATE INDEX idx_rw_violations_result ON realworld_violations(result_id);
CREATE INDEX idx_rw_violations_rule ON realworld_violations(rule_id);
CREATE INDEX idx_gt_lookup ON ground_truth(project, codebase_commit, rule_id);
CREATE INDEX idx_gt_verdict ON ground_truth(verdict);
CREATE INDEX idx_audited_lookup ON audited_files(project, codebase_commit);
