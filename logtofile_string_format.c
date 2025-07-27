/*-------------------------------------------------------------------------
 *
 * logtofile_string_format.c
 *      Functions to format data as strings
 *
 * Copyright (c) 2020-2025, Francisco Miguel Biete Banon
 *
 * This code is released under the PostgreSQL licence, as given at
 *  http://www.postgresql.org/about/licence/
 *-------------------------------------------------------------------------
 */
#include "logtofile_string_format.h"

#include "logtofile_autoclose.h"
#include "logtofile_guc.h"
#include "logtofile_shmem.h"
#include "logtofile_vars.h"

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

#include <pthread.h>
#include <time.h>
#include <sys/stat.h>

#define FORMATTED_TS_LEN 128

/**
 * @brief Formats the session start time
 * @param void
 * @return void
 */
char *PgAuditLogToFile_format_now_timestamp(void)
{

  char *formatted_start_time;

  formatted_start_time = palloc(FORMATTED_TS_LEN * sizeof(char));

  /*
   * Note: we expect that guc.c will ensure that log_timezone is set up (at
   * least with a minimal GMT value) before Log_line_prefix can become
   * nonempty or CSV mode can be selected.
   */
  pg_strftime(formatted_start_time, FORMATTED_TS_LEN, "%Y-%m-%d %H:%M:%S %Z",
              pg_localtime((pg_time_t *)&MyStartTime, log_timezone));

  return formatted_start_time;
}

/**
 * @brief Formats the record time
 * @param void
 * @return void
 */
char *PgAuditLogToFile_format_now_timestamp_millis(void)
{
  char *formatted_log_time;
  struct timeval tv;
  char msbuf[5];

  formatted_log_time = palloc(FORMATTED_TS_LEN * sizeof(char));

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

  return formatted_log_time;
}
