-- pgauditlogtofile uses the log_timezone value for the date pattern
DO $$
DECLARE
  tz text;
BEGIN
  SELECT setting INTO tz
  FROM pg_settings
  WHERE name = 'log_timezone';

  EXECUTE format('SET TIMEZONE = %L', tz);
END$$;


-- search for a text pattern in the current audit log file
CREATE OR REPLACE FUNCTION pgauditlogtofile_regression_audit_log_content(pattern text) RETURNS text AS $$
DECLARE
  content text;
BEGIN
  content := pg_read_file(
      current_setting('data_directory') || '/' ||
      current_setting('pgaudit.log_directory') || '/' || 
      'regression-audit-' || TO_CHAR(NOW(), 'YYYYMMDDHH24') || '.log');
    
  IF strpos(content, pattern) > 0 THEN
    RETURN 'Found';
  ELSE
    RETURN 'Not Found';
  END IF;
END;
$$ LANGUAGE plpgsql;


-- audit log file exists
CREATE OR REPLACE FUNCTION pgauditlogtofile_regression_audit_file_exists() RETURNS boolean AS $$
DECLARE
  compression text := current_setting('pgaudit.log_compression');
  extension text;
  count integer;
BEGIN
  IF compression = 'off' THEN
    extension := '.log';
  ELSIF compression = 'gzip' THEN
    extension := '.log.gz';
  ELSIF compression = 'lz4' THEN
    extension := '.log.lz4';
  ELSIF compression = 'zstd' THEN
    extension := '.log.zst';
  ELSE
    RAISE EXCEPTION 'Unknown compression: %', compression;
    RETURN false;
  END IF;

  SELECT count(*) INTO count
    FROM (SELECT pg_ls_dir(
      current_setting('data_directory') || '/' ||
      current_setting('pgaudit.log_directory')) AS name) AS ls
    WHERE name LIKE 'regression-audit-' || TO_CHAR(NOW(), 'YYYYMMDDHH24') || extension;

  IF count = 1 THEN
    RETURN true;
  ELSE
    RETURN false;
  END IF;
END;
$$ LANGUAGE plpgsql;




-- search for a text pattern in the current postgresql server log file
CREATE OR REPLACE FUNCTION pgauditlogtofile_regression_server_log_content(pattern text) RETURNS text AS $$
DECLARE
  content text;
BEGIN
  content := pg_read_file(
      current_setting('data_directory') || '/' ||
      current_setting('log_directory') || '/' || 
      'regression-server-' || TO_CHAR(NOW(), 'YYYYMMDDHH24') || '.log');

  IF strpos(content, pattern) > 0 THEN
    RETURN 'Found';
  ELSE
    RETURN 'Not Found';
  END IF;
END;
$$ LANGUAGE plpgsql;

-- Force a custom filename for the logs
ALTER SYSTEM SET log_filename = 'regression-server-%Y%m%d%H.log';

ALTER SYSTEM SET pgaudit.log_filename = 'regression-audit-%Y%m%d%H.log';

SELECT pg_reload_conf();

SELECT pg_rotate_logfile();

DO $$
BEGIN
  -- Write one line
  RAISE LOG 'Dummy line to ensure we have file';
END$$;