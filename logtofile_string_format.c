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
#include <stdint.h>

/**
 * @brief Formats the record time
 * @param t instr_time to format
 * @param buf buffer to write the formatted timestamp
 * @param len length of the buffer
 * @return void
 */
void PgAuditLogToFile_format_instr_time_nanos(instr_time t, char *buf, size_t len)
{
  instr_time now_instr;
  instr_time delta;
  TimestampTz now_ts;
  uint64_t delta_micro;
  TimestampTz t_ts;
  struct pg_tm tm;
  fsec_t fsec;
  const char *tzn;
  int tz;
  char tzbuf[16];
  uint64_t nsec;
  size_t cur_len;
  size_t remaining;

  /* capture current wall time and compute delta from provided instr_time */
  INSTR_TIME_SET_CURRENT(now_instr);
  delta = now_instr;
  INSTR_TIME_SUBTRACT(delta, t);

#if PG_VERSION_NUM >= 160000
  /* Use nanosecond resolution where available */
  {
    uint64_t delta_nano = INSTR_TIME_GET_NANOSEC(delta);
    delta_micro = delta_nano / 1000ULL;
  }
#else
  /* Fallback to microsecond resolution on older Postgres */
  delta_micro = INSTR_TIME_GET_MICROSEC(delta);
#endif

  now_ts = GetCurrentTimestamp();
  t_ts = now_ts - (TimestampTz) delta_micro;

  if (timestamp2tm(t_ts, &tz, &tm, &fsec, &tzn, log_timezone) == 0)
  {
    if (tzn == NULL)
    {
      int hours = tz / 3600;
      int mins = abs(tz % 3600) / 60;
      snprintf(tzbuf, sizeof(tzbuf), "%+03d:%02d", hours, mins);
      tzn = tzbuf;
    }
    if (tzn == NULL)
      tzn = "";

    /* Get nanoseconds from instr_time if available; fall back to microseconds*1000 */
  #if PG_VERSION_NUM >= 160000
    nsec = INSTR_TIME_GET_NANOSEC(t) % 1000000000ULL;
  #else
    nsec = (uint64_t) INSTR_TIME_GET_MICROSEC(t) * 1000ULL;
  #endif

    /* Print timestamp without timezone first */
    pg_snprintf(buf, len, "%04d-%02d-%02d %02d:%02d:%02d.%09llu",
          tm.tm_year, tm.tm_mon, tm.tm_mday, tm.tm_hour, tm.tm_min, tm.tm_sec,
          (unsigned long long) nsec);

    /* Safely append a space and the timezone, truncating if necessary */
    cur_len = strnlen(buf, len);
    if (cur_len < len - 1)
    {
      buf[cur_len] = ' ';
      buf[cur_len + 1] = '\0';
      remaining = len - cur_len - 1;
      strlcpy(buf + cur_len + 1, tzn, remaining);
    }
  }
  else
  {
    strlcpy(buf, "[invalid timestamp]", len);
  }
}
