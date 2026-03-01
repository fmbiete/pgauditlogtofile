/*-------------------------------------------------------------------------
 *
 * logtofile_string_format.c
 *      Functions to format data as strings
 *
 * Copyright (c) 2020-2026, Francisco Miguel Biete Banon
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

/**
 * @brief Formats the record time
 * @param buf buffer to write the formatted timestamp
 * @param len length of the buffer
 * @return void
 */
void PgAuditLogToFile_format_now_timestamp_millis(char *buf, size_t len)
{
  struct pg_tm tm;
  fsec_t fsec;
  const char *tzn;
  int tz;

  if (timestamp2tm(GetCurrentTimestamp(), &tz, &tm, &fsec, &tzn, log_timezone) == 0)
  {
    // Ensure we always have a timezone abbreviation. If timestamp2tm() gives NULL, derive one from the timezone object.
    char tzbuf[16];
    if (tzn == NULL)
    {
      /* Format numeric offset like +01:00 */
      int hours = tz / 3600;
      int mins = abs(tz % 3600) / 60;
      snprintf(tzbuf, sizeof(tzbuf), "%+03d:%02d", hours, mins);
      tzn = tzbuf;
    }

    /* As a final fallback, guarantee a non-null string */
    if (tzn == NULL)
      tzn = "";

    pg_snprintf(buf, len, "%04d-%02d-%02d %02d:%02d:%02d.%03d %s",
                tm.tm_year, tm.tm_mon, tm.tm_mday, tm.tm_hour, tm.tm_min, tm.tm_sec,
                (int)(fsec / 1000) /* milliseconds */, tzn);
  }
  else
  {
    strlcpy(buf, "[invalid timestamp]", len);
  }
}
