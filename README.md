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
- Add pgauditlogtofile to "shared_preload_libraries" in postgresql.conf
- Restart PostgreSQL to reload new shared library
- Create extension in postgres database (like pgaudit we don't need to create it in all the databases)

```
postgres=# CREATE EXTENSION pgauditlogtofile;
```

## Configuration

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

### pgaudit.log_rotation_age
Number of minutes after which the audit file will be rotated.

**Scope**: System

**Default**: 1440 minutes (1 day)

**Notes**:
- If _log_rotation_age < 60_ the rotation background worker will wake up every 10 seconds.
- If _log_rotation_age > 60_ the rotation background worker will wake up every 1 minute.
- _log_rotation_age = 0_ will disable the extension and the audit logging will be done to PostgreSQL server logger.

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


### Test
```
cd test
vagrant plugin install vagrant-vbguest
vagrant up
```
