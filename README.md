# pgAudit Log to File

[pgAudit Log to File](https://github.com/fmbiete/pgauditlogtofile) is an addon to [pgAudit](https://www.pgaudit.org/) than will redirect audit log lines to an independent file, instead of using PostgreSQL server logger.

This will allow us to have an audit file that we can easily rotate without polluting server logs with those messages.

Audit logs in heavily used systems can grow very fast. This extension allows to automatically rotate the files based in a number of minutes.

## Build
```
make install USE_PGXS=1
```

## Installation
- Build the extension
- Install pgaudit extension
- Add pgaudit to _shared_preload_libraries_ in postgresql.conf
- Add pgauditlogtofile to _shared_preload_libraries_ in postgresql.conf, after pgaudit
- Restart PostgreSQL to reload new shared library
- Create extension in postgres database (like pgaudit we don't need to create it in all the databases)

## Test
**pg_regres**
```
make installcheck
```

**Vagrant**
```
cd test
vagrant plugin install vagrant-vbguest
vagrant up
```

## Signals
**pgauditlogtofile** listen to multiple signals:
- SIGHUP / pg_reload_conf() : reloads the configuration and triggers a complete rotation.
- SIGUSR1 (against pgauditlogtofile background worker) : closes the audit log file handler in all backends.

**HINT**: Use SIGUSR1 if you find inactive sessions holding file handles and you don't want to enable the auto-close feature.

**ATTENTION**: pg_rotate_logfile() will not rotate or force a close/open for the audit file, because the audit file handles are hold by the backends.



## Configuration

### pgaudit.log_format
Format used to write the audit records.

**Scope**: System

**Default**: 'csv'

**Options**: csv / json

**CSV Notes**: 
- All fields are quoted and escaped when required.
- Statement and Parameters are treated as one unique value.
- Empty values are printed as empty without quotes.

**JSON Notes**: 
- Keys and values are quoted.
- Values are escaped when required.

### pgaudit.log_directory
Name of the directory where the audit file will be created.

**Scope**: System

**Default**: 'log'

Empty or NULL will disable the extension and the audit logging will be done to PostgreSQL server logger.

### pgaudit.log_filename
Name of the file where the audit will be written. Writing to an existing file will append the new entries.

This variable can contain time patterns up to minute to allow automatic rotation.

**Scope**: System

**Default**: 'audit-%Y%m%d_%H%M.log'

Empty or NULL will disable the extension and the audit logging will be done to PostgreSQL server logger.

### pgaudit.log_file_mode
File permissions of the audit log files created.

**Scope**: System

**Default**: '0600'

Permission changes are only applied after file rotation. Files cannot be marked as executable.

### pgaudit.log_rotation_age
Number of minutes after which the audit file will be rotated.

**Scope**: System

**Default**: 1440 minutes (1 day)

**Performance Notes**:
- If _log_rotation_age < 5_ the rotation background worker will wake up every 10 seconds.
- If _log_rotation_age >= 5_ the rotation background worker will wake up every 1 minute.

### pgaudit.log_connections
Intercepts server log messages emited when log_connections is on

**Scope**: System

**Default**: off

**Requires**: log_connections = on

### pgaudit.log_disconnections
Intercepts server log messages emited when log_disconnections is on

**Scope**: System

**Default**: off

**Requires**: log_disconnections = on

### pgaudit.log_autoclose_minutes
**EXPERIMENTAL**: automatically closes the audit log file handler kept by a backend after N minutes of inactivity.

_This features creates a background thread that will sleep in the background and close the file handler._

**Scope**: System

**Default**: 0

### pgaudit.log_execution_time
Measures the execution time of each statement audited in seconds with nanoseconds precision.


**Scope**: System [requires a restart]

**Default**: off


### pgaudit.log_execution_memory
Measures the execution memory footprint of each statement audited.

_This features produces a start, end, delta and peak value._

**Scope**: System [requires a restart]

**Default**: off

### pgaudit.log_compression
Compress the audit log file as independent streams, the resulting file will be always bigger than writing without compression and compressing manually after rotation with an external script.

**Scope**: System

**Default**: off

**Options**: off / gzip / lz4 / zstd

**Performance**: **lz4** is recommended for high load as it provides the best performance (even faster than uncompressed). **zstd** offers a good balance between speed and compression ratio.

#### Performance Benchmark (Transaction per second):
Measured with pgbench and log_compression_level = 0 (default library behavior): 
```
pgbench --client=10 --jobs=2 --time=60 --select-only
```

_Don't consider the tps, your system/configuration will provide different results. The impact ratio is what you should be interested in._


| log_compression value   | impact ratio (% degradation) | tps (without initial connection time)
| :-----------------------| ---------------------------: | ------------------------------------:
| off                     |  0%    | 113700.958346
| gzip                    | 18.77% | 92387.953737
| lz4                     | -0.96% | 114795.996736
| zstd                    |  4.40% | 108699.232205


### pgaudit.log_compression_level
Specifies the compression level for the selected compression algorithm.

**Scope**: System

**Default**: 0 (Default library behavior)

**Range**: 0 to 22




## pgAudit Log To File - Record format
```
CREATE FOREIGN TABLE pgauditlogtofile_extern (
  ----fields from postgresql session----
  log_time timestamptz(9) NULL,
  user_name text NULL,
  database_name text NULL,
  process_id int4 NULL,
  remote_client text NULL,
  remote_port text NULL,
  session_id text NULL,
  session_line_num int8 NULL,
  command_tag text NULL,
  virtual_transaction_id text NULL,
  transaction_id int8 NULL,
  sql_state_code text NULL,
  -----fields from pgaudit record-------
  audit_type text NULL,
  statement_id text NULL,
  substatement_id text NULL,
  "class" text NULL,
  command text NULL,
  object_type text NULL,
  object_name text NULL,
  statement_with_parameters text NULL,
  ----additional fields--------
  detail text NULL,
  hint text NULL,
  internal_query text NULL,
  internal_query_pos int4 NULL,
  context text NULL,
  debug_query text NULL,
  cursor_pos int4 NULL,
  function_name text NULL,
  filename_linenum text NULL,
  application_name text NULL,
  execution_time_start timestamptz(9) NULL,
  execution_time_end timestamptz(9) NULL,
  execution_time double NULL,
  execution_memory_start double NULL,
  execution_memory_end double NULL,
  execution_memory_peak double NULL,
  execution_memory_delta double NULL
)
SERVER your_server
OPTIONS (filename 'audit_log.csv', format 'csv');
```



