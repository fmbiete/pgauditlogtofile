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
#include <utils/timestamp.h>

#define FORMATTED_TS_LEN 64

/**
 * @brief Formats the record time
 * @param void
 * @return void
 */
char *PgAuditLogToFile_format_now_timestamp_millis(void)
{
  char *formatted_log_time;
  struct pg_tm tm;
  fsec_t fsec;
  const char *tzn;

  formatted_log_time = palloc(FORMATTED_TS_LEN);

  if (timestamp2tm(GetCurrentTimestamp(), NULL, &tm, &fsec, &tzn, log_timezone) == 0)
  {
    pg_snprintf(formatted_log_time, FORMATTED_TS_LEN, "%04d-%02d-%02d %02d:%02d:%02d.%03d %s",
                tm.tm_year, tm.tm_mon, tm.tm_mday, tm.tm_hour, tm.tm_min, tm.tm_sec,
                (int)(fsec / 1000) /* milliseconds */, tzn);
  }
  else
  {
    strlcpy(formatted_log_time, "[invalid timestamp]", FORMATTED_TS_LEN);
  }

  return formatted_log_time;
}
