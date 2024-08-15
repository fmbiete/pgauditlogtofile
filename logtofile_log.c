/*-------------------------------------------------------------------------
 *
 * logtofile_log.c
 *      Functions to write audit logs to file
 *
 * Copyright (c) 2020-2024, Francisco Miguel Biete Banon
 *
 * This code is released under the PostgreSQL licence, as given at
 *  http://www.postgresql.org/about/licence/
 *-------------------------------------------------------------------------
 */
#include "logtofile_log.h"

#include "logtofile_autoclose.h"
#include "logtofile_guc.h"
#include "logtofile_shmem.h"
#include "logtofile_vars.h"
#include "logtofile_filename.h"

#include <access/xact.h>
#include <lib/stringinfo.h>
#include <libpq/libpq-be.h>
#include <miscadmin.h>
#include <pgtime.h>
#include <port/atomics.h>
#include <postmaster/syslogger.h>
#include <storage/fd.h>
#include <storage/ipc.h>
#include <storage/lwlock.h>
#include <storage/pg_shmem.h>
#include <storage/proc.h>
#include <tcop/tcopprot.h>
#include <utils/ps_status.h>
#include <utils/wait_event.h>

#include <pthread.h>
#include <time.h>
#include <sys/stat.h>

/* Defines */
#define PGAUDIT_PREFIX_LINE "AUDIT: "
#define PGAUDIT_PREFIX_LINE_LENGTH sizeof(PGAUDIT_PREFIX_LINE) - 1
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

/* variables to use only in this unit */
static char formatted_log_time[FORMATTED_TS_LEN];
static char formatted_start_time[FORMATTED_TS_LEN];
static char filename_in_use[MAXPGPATH];
static int autoclose_thread_status_debug = 0; // 0: new proc, 1: th running, 2: th running sleep used, 3: th closed

/* forward declaration private functions */
void pgauditlogtofile_close_file(void);
void pgauditlogtofile_create_audit_line(StringInfo buf, const ErrorData *edata, int exclude_nchars);
void pgauditlogtofile_format_log_time(void);
void pgauditlogtofile_format_start_time(void);
bool pgauditlogtofile_is_enabled(void);
bool pgauditlogtofile_is_open_file(void);
bool pgauditlogtofile_is_prefixed(const char *msg);
bool pgauditlogtofile_open_file(void);
bool pgauditlogtofile_record_audit(const ErrorData *edata, int exclude_nchars);
bool pgauditlogtofile_write_audit(const ErrorData *edata, int exclude_nchars);

/* public methods */

/**
 * @brief Hook to emit_log - write the record to the audit or send it to the default logger
 * @param edata: error data
 * @return void
 */
void PgAuditLogToFile_emit_log(ErrorData *edata)
{
  int exclude_nchars = -1;

  if (pgauditlogtofile_is_enabled())
  {
    // printf("ENABLE PRINTF\n");
    if (pg_strncasecmp(edata->message, PGAUDIT_PREFIX_LINE, PGAUDIT_PREFIX_LINE_LENGTH) == 0)
    {
      exclude_nchars = PGAUDIT_PREFIX_LINE_LENGTH;
      edata->output_to_server = false;
    }
    else if (pgauditlogtofile_is_prefixed(edata->message))
    {
      edata->output_to_server = false;
      exclude_nchars = 0;
    }

    // Scenarios not contemplated above will be ignored
    if (exclude_nchars >= 0)
    {
      if (!pgauditlogtofile_record_audit(edata, exclude_nchars))
      {
        // ERROR: failed to record in audit, record in server log
        edata->output_to_server = true;
      }
    }
  }

  if (prev_emit_log_hook)
    prev_emit_log_hook(edata);
}

/**
 * @brief Checks if pgauditlogtofile is completely started and configured
 * @param void
 * @return bool - true if pgauditlogtofile is enabled
 */
bool pgauditlogtofile_is_enabled(void)
{
  if (UsedShmemSegAddr == NULL)
    return false;

  if (!pgaudit_ltf_shm || !pg_atomic_unlocked_test_flag(&pgaudit_ltf_flag_shutdown) ||
      guc_pgaudit_ltf_log_directory == NULL || guc_pgaudit_ltf_log_filename == NULL ||
      strlen(guc_pgaudit_ltf_log_directory) == 0 || strlen(guc_pgaudit_ltf_log_filename) == 0)
    return false;

  return true;
}

/**
 * @brief Records an audit log
 * @param edata: error data
 * @param exclude_nchars: number of characters to exclude from the message
 * @return bool - true if the record was written
 */
bool pgauditlogtofile_record_audit(const ErrorData *edata, int exclude_nchars)
{
  bool rc;
  int deviation;

  ereport(DEBUG5, (errmsg("pgauditlogtofile record audit in %s (shm %s)",
                          filename_in_use, pgaudit_ltf_shm->filename)));

  if(!(MyProc == NULL && IsUnderPostmaster) && guc_pgaudit_ltf_log_rotation_size > 0)
  {
    deviation = (int)(guc_pgaudit_ltf_log_rotation_size * 1024L * 0.0009);
    LWLockAcquire(pgaudit_ltf_shm->lock, LW_EXCLUSIVE);
    if (pgaudit_ltf_shm->total_written_bytes + deviation >= guc_pgaudit_ltf_log_rotation_size * 1024L)
    {
      pgaudit_ltf_shm->total_written_bytes = 0;
      LWLockRelease(pgaudit_ltf_shm->lock);
      pgaudit_ltf_shm->size_rotation_flag = true;
      ereport(DEBUG3, (errmsg("pgauditlogtofile the log file size limit has been reached - file update. Current file: %s", pgaudit_ltf_shm->filename)));
      SetLatch(pgaudit_ltf_shm->worker_latch);
    }
    else
    {
      LWLockRelease(pgaudit_ltf_shm->lock);
    }
  }
  /* do we need to rotate? */
  if (strcmp(filename_in_use, pgaudit_ltf_shm->filename) != 0)
  {
    ereport(DEBUG3, (
                        errmsg("pgauditlogtofile record audit file handler requires reopening - shm_filename %s filename_in_use %s",
                               pgaudit_ltf_shm->filename, filename_in_use)));
    pgauditlogtofile_close_file();
  }

  if (!pgauditlogtofile_is_open_file())
  {
    if (!pgauditlogtofile_open_file())
    {
      return false;
    }
  }

  rc = pgauditlogtofile_write_audit(edata, exclude_nchars);
  pgaudit_ltf_autoclose_active_ts = GetCurrentTimestamp();

  if (guc_pgaudit_ltf_auto_close_minutes > 0)
  {
    // only 1 auto-close thread
    if (pg_atomic_test_set_flag(&pgaudit_ltf_autoclose_flag_thread))
    {
      ereport(DEBUG3, (errmsg("pgauditlogtofile record_audit - create autoclose thread")));
      autoclose_thread_status_debug = 1;
      pthread_attr_init(&pgaudit_ltf_autoclose_thread_attr);
      pthread_attr_setdetachstate(&pgaudit_ltf_autoclose_thread_attr, PTHREAD_CREATE_DETACHED);
      pthread_create(&pgaudit_ltf_autoclose_thread, &pgaudit_ltf_autoclose_thread_attr, PgAuditLogToFile_autoclose_run, &autoclose_thread_status_debug);
    }
  }

  return rc;
}

/**
 * @brief Close the audit log file
 * @param void
 * @return void
 */
void pgauditlogtofile_close_file(void)
{
  if (pgaudit_ltf_file_handler)
  {
    fclose(pgaudit_ltf_file_handler);
    pgaudit_ltf_file_handler = NULL;
  }
}

/**
 * @brief Checks if the audit log file is open
 * @param void
 * @return bool - true if the file is open
 */
bool pgauditlogtofile_is_open_file(void)
{
  if (pgaudit_ltf_file_handler)
    return true;
  else
    return false;
}

/**
 * @brief Checks if a message starts with one of our intercept prefixes
 * @param msg: message
 * @return bool - true if the message starts with a prefix
 */
bool pgauditlogtofile_is_prefixed(const char *msg)
{
  bool found = false;
  size_t i;

  if (guc_pgaudit_ltf_log_connections)
  {
    for (i = 0; !found && i < pgaudit_ltf_shm->num_prefixes_connection; i++)
    {
      found = pg_strncasecmp(msg, pgaudit_ltf_shm->prefixes_connection[i]->prefix, pgaudit_ltf_shm->prefixes_connection[i]->length) == 0;
    }
  }

  if (!found && guc_pgaudit_ltf_log_disconnections)
  {
    for (i = 0; !found && i < pgaudit_ltf_shm->num_prefixes_disconnection; i++)
    {
      found = pg_strncasecmp(msg, pgaudit_ltf_shm->prefixes_disconnection[i]->prefix, pgaudit_ltf_shm->prefixes_disconnection[i]->length) == 0;
    }
  }

  return found;
}

/**
 * @brief Open the audit log file
 * @param void
 * @return bool - true if the file was opened
 */
bool pgauditlogtofile_open_file(void)
{
  mode_t oumask;
  bool opened = true;

  /* Create spool directory if not present; ignore errors */
  (void)MakePGDirectory(guc_pgaudit_ltf_log_directory);

  /*
   * Note we do not let Log_file_mode disable IWUSR, since we certainly want
   * to be able to write the files ourselves.
   */
  oumask = umask(
      (mode_t)((~(Log_file_mode | S_IWUSR)) & (S_IRWXU | S_IRWXG | S_IRWXO)));
  pgaudit_ltf_file_handler = fopen(pgaudit_ltf_shm->filename, "a");
  umask(oumask);

  if (pgaudit_ltf_file_handler)
  {
    /* 128K buffer and flush on demand or when full -> attempt to use only 1 IO operation per record */
    setvbuf(pgaudit_ltf_file_handler, NULL, _IOFBF, 131072);
#ifdef WIN32
    /* use CRLF line endings on Windows */
    _setmode(_fileno(file_handler), _O_TEXT);
#endif
    // File open, we update the filename we are using
    strcpy(filename_in_use, pgaudit_ltf_shm->filename);
  }
  else
  {
    int save_errno = errno;
    opened = false;
    ereport(ERROR,
            (errcode_for_file_access(),
             errmsg("could not open log file \"%s\": %m", pgaudit_ltf_shm->filename)));
    errno = save_errno;
  }

  return opened;
}

/**
 * @brief Writes an audit record in the audit log file
 * @param edata: error data
 * @param exclude_nchars: number of characters to exclude from the message
 */
bool pgauditlogtofile_write_audit(const ErrorData *edata, int exclude_nchars)
{
  StringInfoData buf;
  int rc = 0;

  initStringInfo(&buf);
  /* create the log line */
  pgauditlogtofile_create_audit_line(&buf, edata, exclude_nchars);

  // auto-close maybe has closed the file
  if (!pgaudit_ltf_file_handler)
    pgauditlogtofile_open_file();

  if (pgaudit_ltf_file_handler)
  {
    fseek(pgaudit_ltf_file_handler, 0L, SEEK_END);
    rc = fwrite(buf.data, 1, buf.len, pgaudit_ltf_file_handler);
    pfree(buf.data);
    fflush(pgaudit_ltf_file_handler);
  }

  if (rc != buf.len)
  {
    int save_errno = errno;
    ereport(ERROR,
            (errcode_for_file_access(),
             errmsg("could not write audit log file \"%s\": %m", filename_in_use)));
    pgauditlogtofile_close_file();
    errno = save_errno;
  }

  if (rc > 0 && guc_pgaudit_ltf_log_rotation_size > 0)
  {
    if(!(MyProc == NULL && IsUnderPostmaster)){
      LWLockAcquire(pgaudit_ltf_shm->lock, LW_EXCLUSIVE);
      pgaudit_ltf_shm->total_written_bytes += rc;
      LWLockRelease(pgaudit_ltf_shm->lock);
    }
    else{
      pgaudit_ltf_shm->total_written_bytes += rc;
    }
  }

  return rc == buf.len;
}

/**
 * @brief Formats an audit log line
 * @param buf: buffer to write the formatted line
 * @param edata: error data
 * @param exclude_nchars: number of characters to exclude from the message
 * @return void
 */
void pgauditlogtofile_create_audit_line(StringInfo buf, const ErrorData *edata, int exclude_nchars)
{
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
  if (log_my_pid != MyProcPid)
  {
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
  if (MyProcPort && MyProcPort->user_name)
    appendStringInfoString(buf, MyProcPort->user_name);
  appendStringInfoCharMacro(buf, ',');

  /* database name */
  if (MyProcPort && MyProcPort->database_name)
    appendStringInfoString(buf, MyProcPort->database_name);
  appendStringInfoCharMacro(buf, ',');

  /* Process id  */
  appendStringInfo(buf, "%d", log_my_pid);
  appendStringInfoCharMacro(buf, ',');

  /* Remote host and port */
  if (MyProcPort && MyProcPort->remote_host)
  {
    appendStringInfoString(buf, MyProcPort->remote_host);
    if (MyProcPort->remote_port && MyProcPort->remote_port[0] != '\0')
    {
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
  if (MyProcPort)
  {
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
#if (PG_VERSION_NUM >= 170000)
  if (MyProc != NULL && MyProc->vxid.procNumber != INVALID_PROC_NUMBER)
    appendStringInfo(buf, "%d/%u", MyProc->vxid.procNumber, MyProc->vxid.lxid);
#else
  if (MyProc != NULL && MyProc->backendId != InvalidBackendId)
    appendStringInfo(buf, "%d/%u", MyProc->backendId, MyProc->lxid);
#endif
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
  if (Log_error_verbosity >= PGERROR_VERBOSE)
  {
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

/**
 * @brief Formats the session start time
 * @param void
 * @return void
 */
void pgauditlogtofile_format_start_time(void)
{
  /*
   * Note: we expect that guc.c will ensure that log_timezone is set up (at
   * least with a minimal GMT value) before Log_line_prefix can become
   * nonempty or CSV mode can be selected.
   */
  pg_strftime(formatted_start_time, FORMATTED_TS_LEN, "%Y-%m-%d %H:%M:%S %Z",
              pg_localtime((pg_time_t *)&MyStartTime, log_timezone));
}

/**
 * @brief Formats the record time
 * @param void
 * @return void
 */
void pgauditlogtofile_format_log_time(void)
{
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
