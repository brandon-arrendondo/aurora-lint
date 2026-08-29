-- Read-only role for NAS-2's automated pg_dump pull (task 638, plan §7:
-- "NAS-2 pulls its own pg_dump on boot over 5432 -- no SSH, no
-- passphrase-gated TPM key, no human"). Role itself is created separately
-- (needs superuser -- see the shell step run on r720); this does the grants,
-- run as sqc_migrate (owner of every table below).
--
-- SELECT-only, everywhere, including ground_truth -- a backup consumer
-- needs to read every row to dump it, same as pg_dump always requires for
-- any table it's asked to include. This is NOT the same risk as sqc_writer
-- needing no ground_truth access: sqc_writer runs benchmarks and has no
-- business touching the oracle at all, whereas sqc_backup's whole job is
-- reading everything to preserve it, and never writes anything.

GRANT CONNECT ON DATABASE sqc_bench TO sqc_backup;
GRANT USAGE ON SCHEMA public TO sqc_backup;

GRANT SELECT ON
    runs,
    cwe_scans,
    violations,
    cwe_metrics,
    rule_cwe_breakdown,
    realworld_runs,
    realworld_results,
    realworld_violations,
    ground_truth,
    audited_files,
    audit_corpus_meta,
    oracle_versions
TO sqc_backup;
