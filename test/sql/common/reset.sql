ALTER SYSTEM RESET pgaudit.log_directory;

ALTER SYSTEM RESET pgaudit.log_filename;

ALTER SYSTEM RESET pgaudit.log_file_mode;

ALTER SYSTEM RESET pgaudit.log_rotation_age;

ALTER SYSTEM RESET pgaudit.log_connections;

ALTER SYSTEM RESET pgaudit.log_disconnections;

ALTER SYSTEM RESET pgaudit.log_autoclose_minutes;

ALTER SYSTEM RESET pgaudit.log_format;

ALTER SYSTEM RESET pgaudit.log_execution_time;

ALTER SYSTEM RESET pgaudit.log_execution_memory;

ALTER SYSTEM RESET pgaudit.log_compression;

ALTER SYSTEM RESET pgaudit.log_compression_level;

ALTER SYSTEM RESET log_directory;

ALTER SYSTEM RESET log_filename;

ALTER SYSTEM RESET log_file_mode;

ALTER SYSTEM RESET log_connections;

ALTER SYSTEM RESET log_disconnections;

SELECT pg_reload_conf();