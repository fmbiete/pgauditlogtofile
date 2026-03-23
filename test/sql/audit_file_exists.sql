-- Verify that pgaudit.log_directory + pgaudit.log_filename exists with the correct datetime replacements
\i test/sql/common/reset.sql
\i test/sql/common/setup.sql


ALTER SYSTEM SET pgaudit.log_compression = 'off';

SELECT pg_reload_conf();

SELECT 1;

SELECT pgauditlogtofile_regression_audit_file_exists();

-- Repeat the test with compression gzip
ALTER SYSTEM SET pgaudit.log_compression = 'gzip';

SELECT pg_reload_conf();

SELECT 1;

SELECT pgauditlogtofile_regression_audit_file_exists();


-- Repeat the test with compression lz4
ALTER SYSTEM SET pgaudit.log_compression = 'lz4';

SELECT pg_reload_conf();

SELECT 1;

SELECT pgauditlogtofile_regression_audit_file_exists();

-- Repeat the test with compression zstd
ALTER SYSTEM SET pgaudit.log_compression = 'zstd';

SELECT pg_reload_conf();

SELECT 1;

SELECT pgauditlogtofile_regression_audit_file_exists();

-- Clean up
\i test/sql/common/reset.sql
\i test/sql/common/teardown.sql