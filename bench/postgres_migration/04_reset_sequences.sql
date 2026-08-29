-- Run after the bulk load (03_load.sh), before any new benchmark writes to
-- this DB. Plan §4 step 5: loading explicit ids leaves each identity
-- sequence sitting at 1, so the first post-migration insert collides on a
-- duplicate key without this.

SELECT setval(pg_get_serial_sequence('cwe_scans', 'id'),
              COALESCE((SELECT max(id) FROM cwe_scans), 1));
SELECT setval(pg_get_serial_sequence('violations', 'id'),
              COALESCE((SELECT max(id) FROM violations), 1));
SELECT setval(pg_get_serial_sequence('cwe_metrics', 'id'),
              COALESCE((SELECT max(id) FROM cwe_metrics), 1));
SELECT setval(pg_get_serial_sequence('rule_cwe_breakdown', 'id'),
              COALESCE((SELECT max(id) FROM rule_cwe_breakdown), 1));
SELECT setval(pg_get_serial_sequence('realworld_runs', 'id'),
              COALESCE((SELECT max(id) FROM realworld_runs), 1));
SELECT setval(pg_get_serial_sequence('realworld_results', 'id'),
              COALESCE((SELECT max(id) FROM realworld_results), 1));
SELECT setval(pg_get_serial_sequence('realworld_violations', 'id'),
              COALESCE((SELECT max(id) FROM realworld_violations), 1));
SELECT setval(pg_get_serial_sequence('ground_truth', 'id'),
              COALESCE((SELECT max(id) FROM ground_truth), 1));
SELECT setval(pg_get_serial_sequence('audited_files', 'id'),
              COALESCE((SELECT max(id) FROM audited_files), 1));

-- Scoped to our own tables (not `ANALYZE;` bare) so a non-superuser
-- migration role doesn't spray "only superuser can analyze" warnings for
-- every system catalog.
ANALYZE runs, cwe_scans, violations, cwe_metrics, rule_cwe_breakdown,
        realworld_runs, realworld_results, realworld_violations,
        ground_truth, audited_files, audit_corpus_meta, oracle_versions;
