/*-------------------------------------------------------------------------
 *
 * logtofile_filename.c
 *      Functions to calculate the filename of the log file
 *
 * Copyright (c) 2020-2025, Francisco Miguel Biete Banon
 *
 * This code is released under the PostgreSQL licence, as given at
 *  http://www.postgresql.org/about/licence/
 *-------------------------------------------------------------------------
 */
#include "logtofile_filename.h"

#include <pgtime.h>
#include <datatype/timestamp.h>
#include <utils/timestamp.h>

#include "logtofile_vars.h"

// Private functions
char *pgauditlogtofile_tm2filename(const struct pg_tm *tm);

/**
 * @brief Calculate the current filename of the log file
 * @param void
 * @return char * - the current filename
 */
char *
PgAuditLogToFile_current_filename(void)
{
  pg_time_t timet = timestamptz_to_time_t(GetCurrentTimestamp());
  struct pg_tm *tm = pg_localtime(&timet, log_timezone);

  return pgauditlogtofile_tm2filename(tm);
}

/**
 * @brief Set the next rotation time
 * @param void
 * @return void
 * @note Copied from src/backend/postmaster/syslogger.c
 */
void PgAuditLogToFile_set_next_rotation_time(void)
{
  pg_time_t now;
  struct pg_tm *tm;
  int rotinterval;

  /* nothing to do if time-based rotation is disabled */
  if (guc_pgaudit_ltf_log_rotation_age < 1)
    return;

  /*
   * The requirements here are to choose the next time > now that is a
   * "multiple" of the log rotation interval.  "Multiple" can be interpreted
   * fairly loosely.  In this version we align to log_timezone rather than
   * GMT.
   */
  rotinterval = guc_pgaudit_ltf_log_rotation_age * SECS_PER_MINUTE; /* convert to seconds */
  now = (pg_time_t)time(NULL);
  tm = pg_localtime(&now, log_timezone);
  now += tm->tm_gmtoff;
  now -= now % rotinterval;
  now += rotinterval;
  now -= tm->tm_gmtoff;
  LWLockAcquire(pgaudit_ltf_shm->lock, LW_EXCLUSIVE);
  pgaudit_ltf_shm->next_rotation_time = now;
  LWLockRelease(pgaudit_ltf_shm->lock);
}

/**
 * @brief Convert a pg_tm structure to a filename
 * @param tm - the pg_tm structure
 * @return char * - the filename
 */
char *
pgauditlogtofile_tm2filename(const struct pg_tm *tm)
{
  char *filename = NULL;
  int len;

  filename = palloc(MAXPGPATH);

  /* Write directory prefix */
  pg_snprintf(filename, MAXPGPATH, "%s/", guc_pgaudit_ltf_log_directory);

  len = strlen(filename);

  /* Append formatted timestamp-based filename */
  pg_strftime(filename + len, MAXPGPATH - len, guc_pgaudit_ltf_log_filename, tm);

  return filename;
}
