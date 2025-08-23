/*-------------------------------------------------------------------------
 *
 * logtofile_log.c
 *      Functions to write audit logs to file
 *
 * Copyright (c) 2020-2025, Francisco Miguel Biete Banon
 *
 * This code is released under the PostgreSQL licence, as given at
 *  http://www.postgresql.org/about/licence/
 *-------------------------------------------------------------------------
 */
#include "logtofile_log.h"

#include "logtofile_autoclose.h"
#include "logtofile_csv.h"
#include "logtofile_guc.h"
#include "logtofile_json.h"
#include "logtofile_shmem.h"
#include "logtofile_vars.h"

#include <lib/stringinfo.h>
#include <port/atomics.h>
#include <postmaster/syslogger.h>
#include <storage/fd.h>
#include <storage/ipc.h>
#include <storage/lwlock.h>
#include <storage/pg_shmem.h>
#include <utils/timestamp.h>

#include <pthread.h>
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
static char filename_in_use[MAXPGPATH];
static int autoclose_thread_status_debug = 0; // 0: new proc, 1: th running, 2: th running sleep used, 3: th closed

/* forward declaration private functions */
void pgauditlogtofile_close_file(void);
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

  if (pgaudit_ltf_prev_emit_log_hook)
    pgaudit_ltf_prev_emit_log_hook(edata);
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

  ereport(DEBUG5, (errmsg("pgauditlogtofile record audit in %s (shm %s)",
                          filename_in_use, pgaudit_ltf_shm->filename)));
  /* do we need to rotate? */
  if (strlen(pgaudit_ltf_shm->filename) > 0 && strcmp(filename_in_use, pgaudit_ltf_shm->filename) != 0)
  {
    ereport(DEBUG3, (
                        errmsg("pgauditlogtofile record audit file handler requires reopening - shm_filename %s filename_in_use %s",
                               pgaudit_ltf_shm->filename, filename_in_use)));
    pgauditlogtofile_close_file();
  }

  if (!pgauditlogtofile_is_open_file() && !pgauditlogtofile_open_file())
    return false;

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
  bool opened = false;

  // if the filename is empty, we short-circuit
  if (strlen(pgaudit_ltf_shm->filename) == 0)
    return opened;

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
    opened = true;
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
    ereport(LOG_SERVER_ONLY,
            (errcode_for_file_access(),
             errmsg("could not open log file \"%s\": %m", pgaudit_ltf_shm->filename)));
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
  if (pg_strcasecmp(guc_pgaudit_ltf_log_format, "csv") == 0)
    PgAuditLogToFile_csv_audit(&buf, edata, exclude_nchars);
  else if (pg_strcasecmp(guc_pgaudit_ltf_log_format, "json") == 0)
    PgAuditLogToFile_json_audit(&buf, edata, exclude_nchars);

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
    ereport(LOG_SERVER_ONLY,
            (errcode_for_file_access(),
             errmsg("could not write audit log file \"%s\": %m", filename_in_use)));
    pgauditlogtofile_close_file();
  }

  return rc == buf.len;
}