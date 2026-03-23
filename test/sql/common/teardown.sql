-- Clean up
SELECT pg_rotate_logfile();

DROP FUNCTION IF EXISTS pgauditlogtofile_regression_audit_log_content(text);

DROP FUNCTION IF EXISTS pgauditlogtofile_regression_server_log_content(text);

DROP FUNCTION IF EXISTS pgauditlogtofile_regression_audit_file_exists();


-- delete audit file
COPY (
    SELECT 
        current_setting('data_directory') || '/' ||
        current_setting('pgaudit.log_directory') || '/' || 
        'regression-audit-' || TO_CHAR(NOW(), 'YYYYMMDDHH24') || '.log'
) TO PROGRAM 'read path; rm -f "$path"';

COPY (
    SELECT 
        current_setting('data_directory') || '/' ||
        current_setting('pgaudit.log_directory') || '/' || 
        'regression-audit-' || TO_CHAR(NOW(), 'YYYYMMDDHH24') || '.log.gz'
) TO PROGRAM 'read path; rm -f "$path"';

COPY (
    SELECT 
        current_setting('data_directory') || '/' ||
        current_setting('pgaudit.log_directory') || '/' || 
        'regression-audit-' || TO_CHAR(NOW(), 'YYYYMMDDHH24') || '.log.lz4'
) TO PROGRAM 'read path; rm -f "$path"';

COPY (
    SELECT 
        current_setting('data_directory') || '/' ||
        current_setting('pgaudit.log_directory') || '/' || 
        'regression-audit-' || TO_CHAR(NOW(), 'YYYYMMDDHH24') || '.log.zst'
) TO PROGRAM 'read path; rm -f "$path"';

-- delete server log file
COPY (
    SELECT 
        current_setting('data_directory') || '/' ||
        current_setting('log_directory') || '/' || 
        'regression-server-' || TO_CHAR(NOW(), 'YYYYMMDDHH24') || '.log'
) TO PROGRAM 'read path; rm -f "$path"';
