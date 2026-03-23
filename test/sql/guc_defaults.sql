-- Verify GUC defaults
\i test/sql/common/reset.sql

SELECT name, setting
FROM pg_settings
WHERE name IN (
    'pgaudit.log_directory',
    'pgaudit.log_filename',
    'pgaudit.log_file_mode',
    'pgaudit.log_rotation_age',
    'pgaudit.log_connections',
    'pgaudit.log_disconnections',
    'pgaudit.log_autoclose_minutes',
    'pgaudit.log_format',
    'pgaudit.log_execution_time',
    'pgaudit.log_execution_memory',
    'pgaudit.log_compression',
    'pgaudit.log_compression_level'
)
ORDER BY name;

-- Clean up
\i test/sql/common/reset.sql
\i test/sql/common/teardown.sql