/*-------------------------------------------------------------------------
 *
 * logtofile.h
 *      pgaudit addon to redirect audit log lines to an independent file
 *
 * Copyright (c) 2020, Francisco Miguel Biete Banon
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
#include "storage/proc.h"
#include "tcop/tcopprot.h"
#include "utils/guc.h"
#include "utils/memutils.h"
#include "utils/ps_status.h"

#include "logtofile.h"

#include <sys/stat.h>
#include <unistd.h>


#define PGAUDIT_PREFIX_LINE "AUDIT: "

/* GUC Variables */
char *pgaudit_log_directory = NULL;
char *pgaudit_log_filename = NULL;
int pgaudit_log_rotation_age = HOURS_PER_DAY * MINS_PER_HOUR;

/* Hook Functions */
static void pgaudit_emit_log_hook(ErrorData *edata);

/* Old hook storage for loading/unloading of the extension */
static emit_log_hook_type prev_emit_log_hook = NULL;

/* Private state */
static FILE *current_spoolfile = NULL;
static char *current_spoolfile_name = NULL;
static bool rotation_requested = false;
static pg_time_t next_rotation_time;

/*
 * buffers for formatted timestamps
 */
#define FORMATTED_TS_LEN 128
static char formatted_start_time[FORMATTED_TS_LEN];
static char formatted_log_time[FORMATTED_TS_LEN];

/* Internal functions */
static char *get_spoolfile_name(const char *path, pg_time_t timestamp);
static void set_next_rotation_time(void);
static void open_spoolfile(const char *path, pg_time_t timestamp);
static void rotate_spoolfile(const char *path);
static void setup_formatted_log_time(void);
static void setup_formatted_start_time(void);
static inline void appendCSVLiteral(StringInfo buf, const char *data);
static void fmtLogLine(StringInfo buf, ErrorData *edata);
static void pgaudit_emit_log_hook(ErrorData *edata);
static void guc_assign_directory(const char *newval, void *extra);
static void guc_assign_filename(const char *newval, void *extra);
static bool guc_check_directory(char **newval, void **extra, GucSource source);
static void guc_assign_rotation_age(int newval, void *extra);

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

/*
 * construct logfile name using timestamp information
 *
 * Result is palloc'd.
 */
static char *get_spoolfile_name(const char *path, pg_time_t timestamp) {
  char *filename;
  int len;

  filename = palloc(MAXPGPATH);

  snprintf(filename, MAXPGPATH, "%s/", path);

  len = strlen(filename);

  /* treat Log_filename as a strftime pattern */
  pg_strftime(filename + len, MAXPGPATH - len, pgaudit_log_filename,
              pg_localtime(&timestamp, log_timezone));

  return filename;
}

/*
 * Determine the next planned rotation time, and store in next_rotation_time.
 */
static void set_next_rotation_time(void) {
  pg_time_t now;
  struct pg_tm *tm;
  int rotinterval;

  /* nothing to do if time-based rotation is disabled */
  if (pgaudit_log_rotation_age <= 0)
    return;

  /*
   * The requirements here are to choose the next time > now that is a
   * "multiple" of the log rotation interval.
   * "Multiple" can be interpreted fairly loosely
   */
  rotinterval =
      pgaudit_log_rotation_age * SECS_PER_MINUTE; /* convert to seconds */
  now = (pg_time_t)time(NULL);
  tm = pg_localtime(&now, log_timezone);
  now += tm->tm_gmtoff;
  now -= now % rotinterval;
  now += rotinterval;
  now -= tm->tm_gmtoff;
  next_rotation_time = now;
}

/*
 * Open the log spool file
 */
static void open_spoolfile(const char *path, pg_time_t timestamp) {
  const int save_errno = errno;
  char *filename = NULL;
  FILE *fh = NULL;
  mode_t oumask;

  filename = get_spoolfile_name(path, timestamp);

  /*
   * Create spool directory if not present; ignore errors
   */
  mkdir(path, S_IRWXU);

  /*
   * Note we do not let Log_file_mode disable IWUSR, since we certainly want
   * to be able to write the files ourselves.
   */
  oumask = umask(
      (mode_t)((~(Log_file_mode | S_IWUSR)) & (S_IRWXU | S_IRWXG | S_IRWXO)));
  fh = fopen(filename, "a");
  umask(oumask);

  if (fh) {
    setvbuf(fh, NULL, LBF_MODE, 0);

#ifdef WIN32
    /* use CRLF line endings on Windows */
    _setmode(_fileno(fh), _O_TEXT);
#endif

    current_spoolfile = fh;
  } else {
    ereport(LOG, (errcode_for_file_access(),
                  errmsg("could not open log file \"%s\": %m", filename)));
  }
  pfree(filename);
  errno = save_errno;
  return;
}

/*
 * Close the current file (if any) and open a new one
 */
static void rotate_spoolfile(const char *path) {
  /* Close old file and free its name */
  if (current_spoolfile) {
    fclose(current_spoolfile);
    current_spoolfile = NULL;
  }
  if (current_spoolfile_name) {
    pfree(current_spoolfile_name);
    current_spoolfile_name = NULL;
  }

  /* set next planned rotation time */
  set_next_rotation_time();

  /* Open a new log file */
  open_spoolfile(path,
                 next_rotation_time - pgaudit_log_rotation_age * SECS_PER_MINUTE);
}

/*
 * setup formatted_log_time, for consistent times between CSV and regular logs
 */
static void setup_formatted_log_time(void) {
  struct timeval tv;
  pg_time_t stamp_time;
  char msbuf[8];

  gettimeofday(&tv, NULL);
  stamp_time = (pg_time_t)tv.tv_sec;

  /*
   * Note: we expect that guc.c will ensure that log_timezone is set up (at
   * least with a minimal GMT value) before Log_line_prefix can become
   * nonempty or CSV mode can be selected.
   */
  pg_strftime(formatted_log_time, FORMATTED_TS_LEN,
              /* leave room for milliseconds... */
              "%Y-%m-%d %H:%M:%S     %Z",
              pg_localtime(&stamp_time, log_timezone));

  /* 'paste' milliseconds into place... */
  sprintf(msbuf, ".%03d", (int)(tv.tv_usec / 1000));
  strncpy(formatted_log_time + 19, msbuf, 4);
}

/*
 * setup formatted_start_time
 */
static void setup_formatted_start_time(void) {
  pg_time_t stamp_time = (pg_time_t)MyStartTime;

  /*
   * Note: we expect that guc.c will ensure that log_timezone is set up (at
   * least with a minimal GMT value) before Log_line_prefix can become
   * nonempty or CSV mode can be selected.
   */
  pg_strftime(formatted_start_time, FORMATTED_TS_LEN, "%Y-%m-%d %H:%M:%S %Z",
              pg_localtime(&stamp_time, log_timezone));
}

/*
 * append a CSV'd version of a string to a StringInfo
 * We use the PostgreSQL defaults for CSV, i.e. quote = escape = '"'
 * If it's NULL, append nothing.
 */
static inline void appendCSVLiteral(StringInfo buf, const char *data) {
  const char *p = data;
  char c;

  /* avoid confusing an empty string with NULL */
  if (p == NULL)
    return;

  appendStringInfoCharMacro(buf, '"');
  while ((c = *p++) != '\0') {
    if (c == '"')
      appendStringInfoCharMacro(buf, '"');
    appendStringInfoCharMacro(buf, c);
  }
  appendStringInfoCharMacro(buf, '"');
}

/*
 * format the audit line with the full set of prefix values
 */
static void fmtLogLine(StringInfo buf, ErrorData *edata) {
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
    log_line_number = 0;
    log_my_pid = MyProcPid;
    formatted_start_time[0] = '\0';
  }
  log_line_number++;

  /*
   * timestamp with milliseconds
   *
   * Check if the timestamp is already calculated for the syslog message,
   * and use it if so.  Otherwise, get the current timestamp.  This is done
   * to put same timestamp in both syslog and csvlog messages.
   */
  if (formatted_log_time[0] == '\0')
    setup_formatted_log_time();

  appendStringInfoString(buf, formatted_log_time);
  appendStringInfoChar(buf, ',');

  /* username */
  if (MyProcPort)
    appendCSVLiteral(buf, MyProcPort->user_name);
  appendStringInfoChar(buf, ',');

  /* database name */
  if (MyProcPort)
    appendCSVLiteral(buf, MyProcPort->database_name);
  appendStringInfoChar(buf, ',');

  /* Process id  */
  if (MyProcPid != 0)
    appendStringInfo(buf, "%d", MyProcPid);
  appendStringInfoChar(buf, ',');

  /* Remote host and port */
  if (MyProcPort && MyProcPort->remote_host) {
    appendStringInfoChar(buf, '"');
    appendStringInfoString(buf, MyProcPort->remote_host);
    if (MyProcPort->remote_port && MyProcPort->remote_port[0] != '\0') {
      appendStringInfoChar(buf, ':');
      appendStringInfoString(buf, MyProcPort->remote_port);
    }
    appendStringInfoChar(buf, '"');
  }
  appendStringInfoChar(buf, ',');

  /* session id */
  appendStringInfo(buf, "%lx.%x", (long)MyStartTime, MyProcPid);
  appendStringInfoChar(buf, ',');

  /* Line number */
  appendStringInfo(buf, "%ld", log_line_number);
  appendStringInfoChar(buf, ',');

  /* PS display */
  if (MyProcPort) {
    StringInfoData msgbuf;
    const char *psdisp;
    int displen;

    initStringInfo(&msgbuf);

    psdisp = get_ps_display(&displen);
    appendBinaryStringInfo(&msgbuf, psdisp, displen);
    appendCSVLiteral(buf, msgbuf.data);

    pfree(msgbuf.data);
  }
  appendStringInfoChar(buf, ',');

  /* session start timestamp */
  if (formatted_start_time[0] == '\0')
    setup_formatted_start_time();
  appendStringInfoString(buf, formatted_start_time);
  appendStringInfoChar(buf, ',');

  /* Virtual transaction id */
  /* keep VXID format in sync with lockfuncs.c */
  if (MyProc != NULL && MyProc->backendId != InvalidBackendId)
    appendStringInfo(buf, "%d/%u", MyProc->backendId, MyProc->lxid);
  appendStringInfoChar(buf, ',');

  /* Transaction id */
  appendStringInfo(buf, "%u", GetTopTransactionIdIfAny());
  appendStringInfoChar(buf, ',');

  /* SQL state code */
  appendStringInfoString(buf, unpack_sql_state(edata->sqlerrcode));
  appendStringInfoChar(buf, ',');

  /* errmessage */
  appendCSVLiteral(buf, edata->message);
  appendStringInfoChar(buf, ',');

  /* errdetail or errdetail_log */
  if (edata->detail_log)
    appendCSVLiteral(buf, edata->detail_log);
  else
    appendCSVLiteral(buf, edata->detail);
  appendStringInfoChar(buf, ',');

  /* errhint */
  appendCSVLiteral(buf, edata->hint);
  appendStringInfoChar(buf, ',');

  /* internal query */
  appendCSVLiteral(buf, edata->internalquery);
  appendStringInfoChar(buf, ',');

  /* if printed internal query, print internal pos too */
  if (edata->internalpos > 0 && edata->internalquery != NULL)
    appendStringInfo(buf, "%d", edata->internalpos);
  appendStringInfoChar(buf, ',');

  /* errcontext */
  appendCSVLiteral(buf, edata->context);
  appendStringInfoChar(buf, ',');

  /* user query --- only reported if not disabled by the caller */
  if (debug_query_string != NULL && !edata->hide_stmt)
    print_stmt = true;
  if (print_stmt)
    appendCSVLiteral(buf, debug_query_string);
  appendStringInfoChar(buf, ',');
  if (print_stmt && edata->cursorpos > 0)
    appendStringInfo(buf, "%d", edata->cursorpos);
  appendStringInfoChar(buf, ',');

  /* file error location */
  if (Log_error_verbosity >= PGERROR_VERBOSE) {
    StringInfoData msgbuf;

    initStringInfo(&msgbuf);

    if (edata->funcname && edata->filename)
      appendStringInfo(&msgbuf, "%s, %s:%d", edata->funcname, edata->filename,
                       edata->lineno);
    else if (edata->filename)
      appendStringInfo(&msgbuf, "%s:%d", edata->filename, edata->lineno);
    appendCSVLiteral(buf, msgbuf.data);
    pfree(msgbuf.data);
  }
  appendStringInfoChar(buf, ',');

  /* application name */
  if (application_name)
    appendCSVLiteral(buf, application_name);

  appendStringInfoChar(buf, '\n');
}

static void pgaudit_emit_log_hook(ErrorData *edata) {
  int save_errno;
  StringInfoData buf;
  int rc;

  /*
   * Early exit if the spool directory path is not set
   */
  if (pgaudit_log_directory == NULL || strlen(pgaudit_log_directory) <= 0 ||
      pgaudit_log_filename == NULL || strlen(pgaudit_log_filename) <= 0) {
    /*
     * Unsetting the GUCs via SIGHUP would leave a dangling file
     * descriptor, if it exists, close it.
     */
    if (current_spoolfile)
      fclose(current_spoolfile);

    /* Call a previous hook, should it exist */
    if (prev_emit_log_hook != NULL)
      prev_emit_log_hook(edata);

    return;
  }

  /* If it's not a pgaudit log line we will skip it */
  if (pg_strncasecmp(edata->message, PGAUDIT_PREFIX_LINE,
                     strlen(PGAUDIT_PREFIX_LINE)) != 0) {
    /* Call a previous hook, should it exist */
    if (prev_emit_log_hook != NULL)
      prev_emit_log_hook(edata);

    return;
  }

  /* Do a logfile rotation if it's time */
  if ((pg_time_t)time(NULL) >= next_rotation_time) {
    rotation_requested = true;
  }

  save_errno = errno;

  if (current_spoolfile == NULL || rotation_requested) {
    rotate_spoolfile(pgaudit_log_directory);

    /* Couldn't open the destination file; give up */
    if (current_spoolfile == NULL) {
      errno = save_errno;

      /* Call a previous hook, should it exist */
      if (prev_emit_log_hook != NULL)
        prev_emit_log_hook(edata);

      return;
    }
  }

  initStringInfo(&buf);
  /* format the log line */
  fmtLogLine(&buf, edata);

  /* write the log line */
  fseek(current_spoolfile, 0L, SEEK_END);
  rc = fwrite(buf.data, 1, buf.len, current_spoolfile);

  pfree(buf.data);
  errno = save_errno;

  /* If we failed to write the audit to our audit log, use PostgreSQL logger */
  if (rc != buf.len) {
    /* This won't trigger a recursive loop, safe to use */
    ereport(LOG, (errcode_for_file_access(),
                  errmsg("could not write log file \"%s\": %m",
                         current_spoolfile_name)));

    /* Call a previous hook, should it exist */
    if (prev_emit_log_hook != NULL)
      prev_emit_log_hook(edata);

    return;
  }

  /* if we reach this point we don't want the audit line to appear in PostgreSQL
   * server log */
  /*   prev_emit_log_hook is not the default logger */
  edata->output_to_server = false;
}

static void guc_assign_directory(const char *newval, void *extra) {
  /* Force a rotation, but only if there is an open file */
  if (current_spoolfile)
    rotation_requested = true;
}

static void guc_assign_filename(const char *newval, void *extra) {
  /* Force a rotation, but only if there is an open file */
  if (current_spoolfile)
    rotation_requested = true;
}

static bool guc_check_directory(char **newval, void **extra, GucSource source) {
  /*
   * Since canonicalize_path never enlarges the string, we can just modify
   * newval in-place.
   */
  canonicalize_path(*newval);
  return true;
}

static void guc_assign_rotation_age(int newval, void *extra) {
  set_next_rotation_time();
}

/*
 * extension initialization function
 */
void pgauditlogtofile_init(void) {
  /* Set up GUCs */
  DefineCustomStringVariable("pgaudit.log_directory",
                             "Directory where to spool log data", NULL,
                             &pgaudit_log_directory, "log", PGC_SIGHUP,
                             GUC_NOT_IN_SAMPLE | GUC_SUPERUSER_ONLY,
                             guc_check_directory, guc_assign_directory, NULL);

  DefineCustomStringVariable(
      "pgaudit.log_filename",
      "Filename with time patterns (up to minutes) where to spool audit data",
      NULL, &pgaudit_log_filename, "audit-%Y%m%d_%H%M.log", PGC_SIGHUP,
      GUC_NOT_IN_SAMPLE | GUC_SUPERUSER_ONLY, NULL, guc_assign_filename, NULL);

  DefineCustomIntVariable(
      "pgaudit.log_rotation_age",
      "Automatic spool file rotation will occur after N minutes.", NULL,
      &pgaudit_log_rotation_age, HOURS_PER_DAY * MINS_PER_HOUR, 0,
      INT_MAX / SECS_PER_MINUTE, PGC_SIGHUP, GUC_NOT_IN_SAMPLE | GUC_UNIT_MIN,
      NULL, guc_assign_rotation_age, NULL);

  /* Make sure next_rotation_time is set to a sane value */
  set_next_rotation_time();

  /* Install hook */
  prev_emit_log_hook = emit_log_hook;
  emit_log_hook = pgaudit_emit_log_hook;
}

/*
 * extension unloading function
 */
void pgauditlogtofile_fini(void) {
  /* Uninstall hook */
  if (emit_log_hook == pgaudit_emit_log_hook)
    emit_log_hook = prev_emit_log_hook;
}
