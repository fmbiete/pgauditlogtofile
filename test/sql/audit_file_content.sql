-- Validates that audit is written
\i test/sql/common/reset.sql
\i test/sql/common/setup.sql


-- Set audit format to CSV
ALTER SYSTEM SET pgaudit.log_format = 'csv';

SELECT pg_reload_conf();

SELECT /* REGRESSION_CSV_TEST */ 1;

SELECT pgauditlogtofile_regression_audit_log_content('REGRESSION_CSV_TEST');

SELECT pgauditlogtofile_regression_server_log_content('REGRESSION_CSV_TEST');



-- Set audit format to JSON
ALTER SYSTEM SET pgaudit.log_format = 'json';

SELECT pg_reload_conf();

SELECT /* REGRESSION_JSON_TEST */ 1;

SELECT pgauditlogtofile_regression_audit_log_content('REGRESSION_JSON_TEST');

SELECT pgauditlogtofile_regression_server_log_content('REGRESSION_JSON_TEST');



-- Clean up
\i test/sql/common/reset.sql
\i test/sql/common/teardown.sql