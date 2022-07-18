/*-------------------------------------------------------------------------
 *
 * logtofile.c
 *      pgaudit addon to redirect audit log lines to an independent file
 *
 * Copyright (c) 2020-2021, Francisco Miguel Biete Banon
 * Copyright (c) 2014, 2ndQuadrant Ltd.
 *
 * This code is released under the PostgreSQL licence, as given at
 *  http://www.postgresql.org/about/licence/
 *-------------------------------------------------------------------------
 */
#include "postgres.h"
#include "access/xact.h"
#include "libpq/libpq-be.h"
#include "miscadmin.h"
#include "postmaster/syslogger.h"
#include "storage/fd.h"
#include "storage/ipc.h"
#include "storage/pg_shmem.h"
#include "storage/proc.h"
#include "tcop/tcopprot.h"
#include "utils/guc.h"
#include "utils/memutils.h"
#include "utils/ps_status.h"

#include "logtofile.h"

#include <sys/stat.h>
#include <time.h>
#include <unistd.h>
#include <zlib.h>

/* Defines */
#define PGAUDIT_PREFIX_LINE "AUDIT: "
#define PGAUDIT_PREFIX_LINE_LENGTH 7
#define INTERCEPT_DISCONNECTION_PREFIX "disconnection: session time:"
#define INTERCEPT_DISCONNECTION_PREFIX_LENGTH 28
#define INTERCEPT_CONNECTION_PREFIX1 "connection authorized: user="
#define INTERCEPT_CONNECTION_PREFIX1_LENGTH 28
#define INTERCEPT_CONNECTION_PREFIX2 "connection received: host="
#define INTERCEPT_CONNECTION_PREFIX2_LENGTH 26
#define FORMATTED_TS_LEN 128

/*
 * We really want line-buffered mode for logfile output, but Windows does
 * not have it, and interprets _IOLBF as _IOFBF (bozos).  So use _IONBF
 * instead on Windows.
 */
#ifdef WIN32
#define LBF_MODE _IONBF
#else
#define LBF_MODE _IOLBF
#endif

/* Buffers for formatted timestamps */
static char formatted_start_time[FORMATTED_TS_LEN];
static char formatted_log_time[FORMATTED_TS_LEN];

/* SHM structure */
typedef struct pgAuditLogToFileShm {
  LWLock *lock;

  char filename[MAXPGPATH];
  bool force_rotation;
  pg_time_t next_rotation_time;
} pgAuditLogToFileShm;

static pgAuditLogToFileShm *pgaudit_log_shm = NULL;

/* Audit log file handler */
static FILE *file_handler = NULL;
static char filename_in_use[MAXPGPATH];

/* GUC variables */
char *guc_pgaudit_log_directory = NULL;
char *guc_pgaudit_log_filename = NULL;
// Default 1 day rotation
int guc_pgaudit_log_rotation_age = HOURS_PER_DAY * MINS_PER_HOUR;
bool guc_pgaudit_log_connections = false;
bool guc_pgaudit_log_disconnections = false;

/* Old hook storage for loading/unloading of the extension */
static emit_log_hook_type prev_emit_log_hook = NULL;
static shmem_startup_hook_type prev_shmem_startup_hook = NULL;

/* Hook functions */
static void pgauditlogtofile_emit_log(ErrorData *edata);
static void pgauditlogtofile_shmem_startup(void);

/* Internal functions */
static void guc_assign_directory(const char *newval, void *extra);
static void guc_assign_filename(const char *newval, void *extra);
static bool guc_check_directory(char **newval, void **extra, GucSource source);
static void guc_assign_rotation_age(int newval, void *extra);

static void pgauditlogtofile_request_rotation(void);
static void pgauditlogtofile_calculate_filename(void);
static pg_time_t pgauditlogtofile_calculate_next_rotation_time(void);
static void pgauditlogtofile_close_file(void);
static void pgauditlogtofile_format_audit_line(StringInfo buf, const ErrorData *edata, int exclude_nchars);
static void pgauditlogtofile_format_log_time(void);
static void pgauditlogtofile_format_start_time(void);
static bool pgauditlogtofile_is_enabled(void);
static bool pgauditlogtofile_is_open_file(void);
static bool pgauditlogtofile_needs_rotate_file(void);
static bool pgauditlogtofile_open_file(void);
static bool pgauditlogtofile_record_audit(const ErrorData *edata, int exclude_nchars);
static bool pgauditlogtofile_write_audit(const ErrorData *edata, int exclude_nchars);


static void pgauditlogtofile_request_rotation(void) {
  /* Directory is changed force a rotation */
  if (UsedShmemSegAddr == NULL)
  	return;

  if (!pgaudit_log_shm->force_rotation) {
    LWLockAcquire(pgaudit_log_shm->lock, LW_EXCLUSIVE);
    pgaudit_log_shm->force_rotation = true;
    LWLockRelease(pgaudit_log_shm->lock);
  }
}

/*
 * GUC Callback pgaudit.log_directory changes
 */
static void guc_assign_directory(const char *newval, void *extra) {
  pgauditlogtofile_request_rotation();
}

/*
 * GUC Callback pgaudit.log_filename changes
 */
static void guc_assign_filename(const char *newval, void *extra) {
  pgauditlogtofile_request_rotation();
}

/*
 * GUC Callback pgaudit.log_directory check path
 */
static bool guc_check_directory(char **newval, void **extra, GucSource source) {
  /*
   * Since canonicalize_path never enlarges the string, we can just modify
   * newval in-place.
   */
  canonicalize_path(*newval);
  return true;
}

/*
 * GUC Callback pgaudit.rotation_age changes
 */
static void guc_assign_rotation_age(int newval, void *extra) {
  pgauditlogtofile_request_rotation();
}

/*
 * Extension Init Callback
 */
void _PG_init(void) {
  DefineCustomStringVariable(
    "pgaudit.log_directory",
    "Directory where to spool log data", NULL,
    &guc_pgaudit_log_directory, "log", PGC_SIGHUP,
    GUC_NOT_IN_SAMPLE | GUC_SUPERUSER_ONLY,
    guc_check_directory, guc_assign_directory, NULL);

  DefineCustomStringVariable(
    "pgaudit.log_filename",
    "Filename with time patterns (up to minutes) where to spool audit data",
    NULL, &guc_pgaudit_log_filename, "audit-%Y%m%d_%H%M.log", PGC_SIGHUP,
    GUC_NOT_IN_SAMPLE | GUC_SUPERUSER_ONLY, NULL, guc_assign_filename, NULL);

  DefineCustomIntVariable(
    "pgaudit.log_rotation_age",
    "Automatic spool file rotation will occur after N minutes", NULL,
    &guc_pgaudit_log_rotation_age, HOURS_PER_DAY * MINS_PER_HOUR, 0,
    INT_MAX / SECS_PER_MINUTE, PGC_SIGHUP,
    GUC_NOT_IN_SAMPLE | GUC_UNIT_MIN | GUC_SUPERUSER_ONLY, NULL,
    guc_assign_rotation_age, NULL);

  DefineCustomBoolVariable(
    "pgaudit.log_connections",
    "Intercepts log_connections messages", NULL,
    &guc_pgaudit_log_connections, false, PGC_SIGHUP,
    GUC_NOT_IN_SAMPLE | GUC_SUPERUSER_ONLY, NULL, NULL, NULL);

  DefineCustomBoolVariable(
    "pgaudit.log_disconnections",
    "Intercepts log_disconnections messages", NULL,
    &guc_pgaudit_log_disconnections, false, PGC_SIGHUP,
    GUC_NOT_IN_SAMPLE | GUC_SUPERUSER_ONLY, NULL, NULL, NULL);

  EmitWarningsOnPlaceholders("pgauditlogtofile");

  RequestAddinShmemSpace(MAXALIGN(sizeof(pgAuditLogToFileShm)));
  RequestNamedLWLockTranche("pgauditlogtofile", 1);

  prev_shmem_startup_hook = shmem_startup_hook;
  shmem_startup_hook = pgauditlogtofile_shmem_startup;
  prev_emit_log_hook = emit_log_hook;
  emit_log_hook = pgauditlogtofile_emit_log;
}

/*
 * Extension Fin Callback
 */
void _PG_fini(void) {
  emit_log_hook = prev_emit_log_hook;
  shmem_startup_hook = prev_shmem_startup_hook;
}

/*
 * SHMEM startup hook - Initialize SHMEM structure
 */
static void pgauditlogtofile_shmem_startup(void) {
  bool found;

  if (prev_shmem_startup_hook)
    prev_shmem_startup_hook();

  /* reset in case this is a restart within the postmaster */
  pgaudit_log_shm = NULL;

  LWLockAcquire(AddinShmemInitLock, LW_EXCLUSIVE);
  pgaudit_log_shm =
      ShmemInitStruct("pgauditlogtofile", sizeof(pgAuditLogToFileShm), &found);
  if (!found) {
    pgaudit_log_shm->lock = &(GetNamedLWLockTranche("pgauditlogtofile"))->lock;
    /* We force a rotation on initialization */
    pgaudit_log_shm->force_rotation = true;
    pgaudit_log_shm->next_rotation_time =
        pgauditlogtofile_calculate_next_rotation_time();
  }
  LWLockRelease(AddinShmemInitLock);

  if (!found) {
    ereport(LOG, (errmsg("pgauditlogtofile extension initialized")));
  }
}

/*
 * Hook to emit_log - write the record to the audit or send it to the default
 * logger
 */
static void pgauditlogtofile_emit_log(ErrorData *edata) {
  int exclude_nchars = -2;

  if (pgauditlogtofile_is_enabled()) {
    if (pg_strncasecmp(edata->message, PGAUDIT_PREFIX_LINE, PGAUDIT_PREFIX_LINE_LENGTH) == 0)
      exclude_nchars = PGAUDIT_PREFIX_LINE_LENGTH;
    else if (pg_strncasecmp(edata->message, INTERCEPT_CONNECTION_PREFIX1, INTERCEPT_CONNECTION_PREFIX1_LENGTH) == 0)
      exclude_nchars = 0;
    else if (pg_strncasecmp(edata->message, INTERCEPT_CONNECTION_PREFIX2, INTERCEPT_CONNECTION_PREFIX2_LENGTH) == 0) {
      // We want to hide "connection received" messages, but we cannot log them because MyProcPort is not fully populated yet
      exclude_nchars = -1;
    }
    else if (pg_strncasecmp(edata->message, INTERCEPT_DISCONNECTION_PREFIX, INTERCEPT_DISCONNECTION_PREFIX_LENGTH) == 0)
      exclude_nchars = 0;

    if (exclude_nchars > -2) {
      if (exclude_nchars == -1 || MyProc == NULL) {
        edata->output_to_server = false;
      } else {
        if (pgauditlogtofile_record_audit(edata, exclude_nchars)) {
          edata->output_to_server = false;
        }
      }
    }
  }

  if (prev_emit_log_hook)
    prev_emit_log_hook(edata);
}

/*
 * Checks if pgauditlogtofile is completely started and configured
 */
static inline bool pgauditlogtofile_is_enabled(void) {
  if (!pgaudit_log_shm || guc_pgaudit_log_directory == NULL ||
      guc_pgaudit_log_filename == NULL ||
      strlen(guc_pgaudit_log_directory) == 0 ||
      strlen(guc_pgaudit_log_filename) == 0)
    return false;

  return true;
}

/*
 * Records an audit log
 */
static bool pgauditlogtofile_record_audit(const ErrorData *edata, int exclude_nchars) {
  if (pgauditlogtofile_needs_rotate_file()) {
    // calculate_filename will generate a new global file
    pgauditlogtofile_calculate_filename();
    pgauditlogtofile_close_file();
  }

  if (!pgauditlogtofile_is_open_file()) {
    if (!pgauditlogtofile_open_file()) {
      // ERROR: unable to open file
      return false;
    }
  }

  return pgauditlogtofile_write_audit(edata, exclude_nchars);
}

/*
 * Close audit log file
 */
static inline void pgauditlogtofile_close_file(void) {
  if (file_handler) {
    fclose(file_handler);
    file_handler = NULL;
  }
}

/*
 * Checks if the audit log file is open
 */
static inline bool pgauditlogtofile_is_open_file(void) {
  if (file_handler)
    return true;
  else
    return false;
}

/*
 * Checks if the audit log file needs to be rotated before we use it
 */
static bool pgauditlogtofile_needs_rotate_file(void) {
  /* Rotate if we are forcing */
  if (pgaudit_log_shm->force_rotation) {
    LWLockAcquire(pgaudit_log_shm->lock, LW_EXCLUSIVE);
    pgaudit_log_shm->force_rotation = false;
    LWLockRelease(pgaudit_log_shm->lock);
    return true;
  }


  /* Rotate if rotation_age is exceeded, and this backend is the first in notice
   * it */
  if ((pg_time_t)time(NULL) >= pgaudit_log_shm->next_rotation_time) {
    LWLockAcquire(pgaudit_log_shm->lock, LW_EXCLUSIVE);
    pgaudit_log_shm->next_rotation_time =
        pgauditlogtofile_calculate_next_rotation_time();
    LWLockRelease(pgaudit_log_shm->lock);
    return true;
  }

  /* Rotate if the global name is different to this backend copy: it has been
   * rotated */
  if (strcmp(filename_in_use, pgaudit_log_shm->filename) != 0) {
    return true;
  }

  return false;
}

/*
 * Calculates next rotation time
 */
static pg_time_t pgauditlogtofile_calculate_next_rotation_time(void) {
  pg_time_t now = (pg_time_t)time(NULL);
  struct pg_tm *tm = pg_localtime(&now, log_timezone);
  int rotinterval =
      guc_pgaudit_log_rotation_age * SECS_PER_MINUTE; /* Convert to seconds */

  /* Calculate the new rotation date based in current date + rotation interval
   */
  now += tm->tm_gmtoff;
  now -= now % rotinterval; /* try to get the o'clock hour of next rotation */
  now += rotinterval;
  now -= tm->tm_gmtoff;

  return now;
}

/*
 * Open audit log
 */
static bool pgauditlogtofile_open_file(void) {
  mode_t oumask;
  bool opened = true;

  /* Create spool directory if not present; ignore errors */
  #if PG_MAJORVERSION_NUM < 11
    mkdir(guc_pgaudit_log_directory, S_IRWXU);
  #else
    (void)MakePGDirectory(guc_pgaudit_log_directory);
  #endif

  /*
   * Note we do not let Log_file_mode disable IWUSR, since we certainly want
   * to be able to write the files ourselves.
   */

  LWLockAcquire(pgaudit_log_shm->lock, LW_SHARED);
  oumask = umask(
      (mode_t)((~(Log_file_mode | S_IWUSR)) & (S_IRWXU | S_IRWXG | S_IRWXO)));
  file_handler = fopen(pgaudit_log_shm->filename, "a");
  umask(oumask);

  if (file_handler) {
    /* 128K buffer and flush on demand or when full -> attempt to use only 1 IO operation per record */
    setvbuf(file_handler, NULL, _IOFBF, 131072);
#ifdef WIN32
    /* use CRLF line endings on Windows */
    _setmode(_fileno(file_handler), _O_TEXT);
#endif
    // File open, we update the pgaudit_log_shm->filename we are using
    strcpy(filename_in_use, pgaudit_log_shm->filename);
  } else {
    int save_errno = errno;
    opened = false;
    ereport(WARNING, (errcode_for_file_access(),
                      errmsg("could not open log file \"%s\": %m",
                             pgaudit_log_shm->filename)));
    errno = save_errno;
  }
  LWLockRelease(pgaudit_log_shm->lock);

  return opened;
}

/*
 * Generates the name fo the audit log file
 */
static void pgauditlogtofile_calculate_filename(void) {
  int len;
  pg_time_t current_rotation_time =
      pgaudit_log_shm->next_rotation_time -
      guc_pgaudit_log_rotation_age * SECS_PER_MINUTE;

  LWLockAcquire(pgaudit_log_shm->lock, LW_EXCLUSIVE);
  memset(pgaudit_log_shm->filename, 0, sizeof(pgaudit_log_shm->filename));
  snprintf(pgaudit_log_shm->filename, MAXPGPATH, "%s/",
           guc_pgaudit_log_directory);
  len = strlen(pgaudit_log_shm->filename);
  /* treat Log_pgaudit_log_shm->filename as a strftime pattern */
  pg_strftime(pgaudit_log_shm->filename + len, MAXPGPATH - len,
              guc_pgaudit_log_filename,
              pg_localtime(&current_rotation_time, log_timezone));
  LWLockRelease(pgaudit_log_shm->lock);
}

/*
 * Writes an audit record in the audit log file
 */
static bool pgauditlogtofile_write_audit(const ErrorData *edata, int exclude_nchars) {
  StringInfoData buf;
  int rc;

  initStringInfo(&buf);
  /* format the log line */
  pgauditlogtofile_format_audit_line(&buf, edata, exclude_nchars);
  LWLockAcquire(pgaudit_log_shm->lock, LW_EXCLUSIVE);
  fseek(file_handler, 0L, SEEK_END);
  rc = fwrite(buf.data, 1, buf.len, file_handler);
  pfree(buf.data);
  fflush(file_handler);
  LWLockRelease(pgaudit_log_shm->lock);

  /* If we failed to write the audit to our audit log, use PostgreSQL logger */
  if (rc != buf.len) {
    int save_errno = errno;
    ereport(WARNING, (errcode_for_file_access(),
                      errmsg("could not write audit log file \"%s\": %m",
                             pgaudit_log_shm->filename)));
    errno = save_errno;
  }

  return rc == buf.len;
}

/*
 * Formats an audit log line
 */
static void pgauditlogtofile_format_audit_line(StringInfo buf, const ErrorData *edata, int exclude_nchars) {
  bool print_stmt = false;

  /* static counter for line numbers */
  static long log_line_number = 0;

  /* has counter been reset in current process? */
  static int log_my_pid = 0;

  /*
   * This is one of the few places where we'd rather not inherit a static
   * variable's value from the postmaster.  But since we will, reset it when
   * MyProcPid changes.
   */
  if (log_my_pid != MyProcPid) {
    /* new session */
    log_line_number = 0;
    log_my_pid = MyProcPid;
    /* start session timestamp */
    pgauditlogtofile_format_start_time();
  }
  log_line_number++;

  /* timestamp with milliseconds */
  pgauditlogtofile_format_log_time();
  appendStringInfoString(buf, formatted_log_time);
  appendStringInfoCharMacro(buf, ',');

  /* username */
  if (MyProcPort)
    appendStringInfoString(buf, MyProcPort->user_name);
  appendStringInfoCharMacro(buf, ',');

  /* database name */
  if (MyProcPort)
    appendStringInfoString(buf, MyProcPort->database_name);
  appendStringInfoCharMacro(buf, ',');

  /* Process id  */
  appendStringInfo(buf, "%d", log_my_pid);
  appendStringInfoCharMacro(buf, ',');

  /* Remote host and port */
  if (MyProcPort && MyProcPort->remote_host) {
    appendStringInfoString(buf, MyProcPort->remote_host);
    if (MyProcPort->remote_port && MyProcPort->remote_port[0] != '\0') {
      appendStringInfoCharMacro(buf, ':');
      appendStringInfoString(buf, MyProcPort->remote_port);
    }
  }
  appendStringInfoCharMacro(buf, ',');

  /* session id - hex representation of start time . session process id */
  appendStringInfo(buf, "%lx.%x", (long)MyStartTime, log_my_pid);
  appendStringInfoCharMacro(buf, ',');

  /* Line number */
  appendStringInfo(buf, "%ld", log_line_number);
  appendStringInfoCharMacro(buf, ',');

  /* PS display */
  if (MyProcPort) {
    StringInfoData msgbuf;
    const char *psdisp;
    int displen;

    initStringInfo(&msgbuf);

    psdisp = get_ps_display(&displen);
    appendBinaryStringInfo(&msgbuf, psdisp, displen);
    appendStringInfoString(buf, msgbuf.data);

    pfree(msgbuf.data);
  }
  appendStringInfoCharMacro(buf, ',');

  /* session start timestamp */
  appendStringInfoString(buf, formatted_start_time);
  appendStringInfoCharMacro(buf, ',');

  /* Virtual transaction id */
  /* keep VXID format in sync with lockfuncs.c */
  if (MyProc != NULL && MyProc->backendId != InvalidBackendId)
    appendStringInfo(buf, "%d/%u", MyProc->backendId, MyProc->lxid);
  appendStringInfoCharMacro(buf, ',');

  /* Transaction id */
  appendStringInfo(buf, "%u", GetTopTransactionIdIfAny());
  appendStringInfoCharMacro(buf, ',');

  /* SQL state code */
  appendStringInfoString(buf, unpack_sql_state(edata->sqlerrcode));
  appendStringInfoCharMacro(buf, ',');

  /* errmessage - PGAUDIT formatted text, +7 exclude "AUDIT: " prefix */
  appendStringInfoString(buf, edata->message + exclude_nchars);
  appendStringInfoCharMacro(buf, ',');

  /* errdetail or errdetail_log */
  if (edata->detail_log)
    appendStringInfoString(buf, edata->detail_log);
  else if (edata->detail)
    appendStringInfoString(buf, edata->detail);
  appendStringInfoCharMacro(buf, ',');

  /* errhint */
  if (edata->hint)
    appendStringInfoString(buf, edata->hint);
  appendStringInfoCharMacro(buf, ',');

  /* internal query */
  if (edata->internalquery)
    appendStringInfoString(buf, edata->internalquery);
  appendStringInfoCharMacro(buf, ',');

  /* if printed internal query, print internal pos too */
  if (edata->internalpos > 0 && edata->internalquery != NULL)
    appendStringInfo(buf, "%d", edata->internalpos);
  appendStringInfoCharMacro(buf, ',');

  /* errcontext */
  if (edata->context)
    appendStringInfoString(buf, edata->context);
  appendStringInfoCharMacro(buf, ',');

  /* user query --- only reported if not disabled by the caller */
  if (debug_query_string != NULL && !edata->hide_stmt)
    print_stmt = true;
  if (print_stmt)
    appendStringInfoString(buf, debug_query_string);
  appendStringInfoCharMacro(buf, ',');
  if (print_stmt && edata->cursorpos > 0)
    appendStringInfo(buf, "%d", edata->cursorpos);
  appendStringInfoCharMacro(buf, ',');

  /* file error location */
  if (Log_error_verbosity >= PGERROR_VERBOSE) {
    StringInfoData msgbuf;

    initStringInfo(&msgbuf);

    if (edata->funcname && edata->filename)
      appendStringInfo(&msgbuf, "%s, %s:%d", edata->funcname, edata->filename,
                       edata->lineno);
    else if (edata->filename)
      appendStringInfo(&msgbuf, "%s:%d", edata->filename, edata->lineno);
    appendStringInfoString(buf, msgbuf.data);
    pfree(msgbuf.data);
  }
  appendStringInfoCharMacro(buf, ',');

  /* application name */
  if (application_name)
    appendStringInfoString(buf, application_name);

  appendStringInfoCharMacro(buf, '\n');
}

/*
 * Formats the session start time
 */
static inline void pgauditlogtofile_format_start_time(void) {
  /*
   * Note: we expect that guc.c will ensure that log_timezone is set up (at
   * least with a minimal GMT value) before Log_line_prefix can become
   * nonempty or CSV mode can be selected.
   */
  pg_strftime(formatted_start_time, FORMATTED_TS_LEN, "%Y-%m-%d %H:%M:%S %Z",
              pg_localtime((pg_time_t *)&MyStartTime, log_timezone));
}

/*
 * Formats the record time
 */
static inline void pgauditlogtofile_format_log_time(void) {
  struct timeval tv;
  char msbuf[5];

  gettimeofday(&tv, NULL);

  /*
   * Note: we expect that guc.c will ensure that log_timezone is set up (at
   * least with a minimal GMT value) before Log_line_prefix can become
   * nonempty or CSV mode can be selected.
   */
  pg_strftime(formatted_log_time, FORMATTED_TS_LEN,
              /* leave room for milliseconds... */
              "%Y-%m-%d %H:%M:%S     %Z",
              pg_localtime((pg_time_t *)&(tv.tv_sec), log_timezone));

  /* 'paste' milliseconds into place... */
  sprintf(msbuf, ".%03d", (int)(tv.tv_usec / 1000));
  memcpy(formatted_log_time + 19, msbuf, 4);
}
