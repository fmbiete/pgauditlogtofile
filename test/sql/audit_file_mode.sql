-- Test file mode setting
\i test/sql/common/reset.sql
\i test/sql/common/setup.sql

-- Create a new audit file
ALTER SYSTEM SET pgaudit.log_filename = 'regression-audit-file-mode.log';
-- Set file mode to 0600
ALTER SYSTEM SET pgaudit.log_file_mode = '0600';

SELECT pg_reload_conf();

-- Generate a log entry to create the file
SELECT /* FILE-MODE-TEST */ pg_sleep(1);


-- 1. Use COPY to write the exact shell command to a temporary file
COPY (
    SELECT 'stat -c "%a" ' || 
           current_setting('data_directory') || '/' ||
           current_setting('pgaudit.log_directory') || '/' || 
           current_setting('pgaudit.log_filename')
) TO '/tmp/get_mode.sh';

-- 2. Execute that generated script file
\! sh /tmp/get_mode.sh

-- 3. Clean up
\! rm /tmp/get_mode.sh


-- Clean up
ALTER SYSTEM RESET pgaudit.log_filename;
ALTER SYSTEM RESET pgaudit.log_file_mode;
SELECT pg_reload_conf();

COPY (
    SELECT 
        current_setting('data_directory') || '/' ||
        current_setting('pgaudit.log_directory') || '/' || 
        'regression-audit-file-mode.log'
) TO PROGRAM 'read path; rm -f "$path"';

\i test/sql/common/reset.sql
\i test/sql/common/teardown.sql