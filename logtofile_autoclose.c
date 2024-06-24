/*-------------------------------------------------------------------------
 *
 * logtofile_autoclose.c
 *      Autoclose thread for logtofile
 *
 * Copyright (c) 2020-2024, Francisco Miguel Biete Banon
 *
 * This code is released under the PostgreSQL licence, as given at
 *  http://www.postgresql.org/about/licence/
 *-------------------------------------------------------------------------
 */
#include "logtofile_autoclose.h"

#include "logtofile_vars.h"

#include <datatype/timestamp.h>
#include <port/atomics.h>
#include <utils/timestamp.h>

#include <pthread.h>
#include <unistd.h>

/**
 * @brief Main thread function to close the audit log file after a certain time
 * @param arg: autoclose_thread_status_debug - used to debug the thread status
 * @return void
 */
void *PgAuditLogToFile_autoclose_run(void *arg)
{
  int64 diff;
  TimestampTz ts_now;
  long secs;
  int microsecs;
  int *autoclose_thread_status_debug;

  // don't use ereport here, use this flag to identify the position
  autoclose_thread_status_debug = (int *)arg;

  while (1)
  {
    sleep(1 * SECS_PER_MINUTE);
    ts_now = GetCurrentTimestamp();
    TimestampDifference(pgaudit_ltf_autoclose_active_ts, ts_now, &secs, &microsecs);
    diff = secs / SECS_PER_MINUTE;
    if (diff >= guc_pgaudit_ltf_auto_close_minutes)
    {
      fclose(pgaudit_ltf_file_handler);
      pgaudit_ltf_file_handler = NULL;
      *autoclose_thread_status_debug = 3; // file closed
      break;
    }
    else
    {
      *autoclose_thread_status_debug = 2; // file recently used
    }
  }

  // clear the flag to allow another thread creation
  pg_atomic_clear_flag(&pgaudit_ltf_autoclose_flag_thread);
  pthread_exit(NULL);
}
