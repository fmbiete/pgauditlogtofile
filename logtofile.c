/*-------------------------------------------------------------------------
 *
 * logtofile.c
 *      Main entry point for logtofile
 *
 * Copyright (c) 2020-2024, Francisco Miguel Biete Banon
 *
 * This code is released under the PostgreSQL licence, as given at
 *  http://www.postgresql.org/about/licence/
 *-------------------------------------------------------------------------
 */
#include "logtofile.h"

#include "logtofile_bgw.h"
#include "logtofile_connect.h"
#include "logtofile_guc.h"
#include "logtofile_log.h"
#include "logtofile_shmem.h"
#include "logtofile_vars.h"

#include <postgres.h>

/* these are always necessary for a bgworker */
#include <miscadmin.h>
#include <postmaster/bgworker.h>
#include <storage/ipc.h>
#include <storage/latch.h>
#include <storage/lwlock.h>
#include <storage/proc.h>
#include <storage/shm_mq.h>
#include <storage/shm_toc.h>
#include <storage/shmem.h>

#include <utils/guc.h>
#include <datatype/timestamp.h>
#include <pgstat.h>

/**
 * @brief Main entry point for the extension
 * @param void
 * @return void
*/
void _PG_init(void)
{
  BackgroundWorker worker;

  if (!process_shared_preload_libraries_in_progress)
  {
    ereport(ERROR, (
                       errmsg("pgauditlogtofile can only be loaded via shared_preload_libraries"),
                       errhint("Add pgauditlogtofile to the shared_preload_libraries configuration variable in postgresql.conf.")));
  }

  /* guc variables */
  DefineCustomStringVariable(
      "pgaudit.log_directory",
      "Directory where to spool log data", NULL,
      &guc_pgaudit_ltf_log_directory, "log", PGC_SIGHUP,
      GUC_NOT_IN_SAMPLE | GUC_SUPERUSER_ONLY,
      guc_check_directory, NULL, NULL);

  DefineCustomStringVariable(
      "pgaudit.log_filename",
      "Filename with time patterns (up to minutes) where to spool audit data",
      NULL, &guc_pgaudit_ltf_log_filename, "audit-%Y%m%d_%H%M.log", PGC_SIGHUP,
      GUC_NOT_IN_SAMPLE | GUC_SUPERUSER_ONLY, NULL, NULL, NULL);

  DefineCustomIntVariable(
      "pgaudit.log_rotation_age",
      "Automatic spool file rotation will occur after N minutes", NULL,
      &guc_pgaudit_ltf_log_rotation_age, HOURS_PER_DAY * MINS_PER_HOUR, 1,
      INT_MAX / SECS_PER_MINUTE, PGC_SIGHUP,
      GUC_NOT_IN_SAMPLE | GUC_UNIT_MIN | GUC_SUPERUSER_ONLY, NULL, NULL, NULL);

  DefineCustomIntVariable(
    "pgaudit.log_rotation_size",
    "Automatic rotation of logfiles will happen after that much log output", NULL,
    &guc_pgaudit_ltf_log_rotation_size, 0, 0, INT_MAX / 1024, PGC_SIGHUP,
    GUC_NOT_IN_SAMPLE | GUC_SUPERUSER_ONLY | GUC_UNIT_KB, NULL, NULL, NULL);

  DefineCustomBoolVariable(
      "pgaudit.log_connections",
      "Intercepts log_connections messages", NULL,
      &guc_pgaudit_ltf_log_connections, false, PGC_SIGHUP,
      GUC_NOT_IN_SAMPLE | GUC_SUPERUSER_ONLY, NULL, NULL, NULL);

  DefineCustomBoolVariable(
      "pgaudit.log_disconnections",
      "Intercepts log_disconnections messages", NULL,
      &guc_pgaudit_ltf_log_disconnections, false, PGC_SIGHUP,
      GUC_NOT_IN_SAMPLE | GUC_SUPERUSER_ONLY, NULL, NULL, NULL);

  DefineCustomIntVariable(
      "pgaudit.log_autoclose_minutes",
      "Automatic spool file closure by backend after N minutes of inactivity", NULL,
      &guc_pgaudit_ltf_auto_close_minutes, 0, 0,
      INT_MAX / MINS_PER_HOUR, PGC_SIGHUP,
      GUC_NOT_IN_SAMPLE | GUC_UNIT_MIN | GUC_SUPERUSER_ONLY, NULL, NULL, NULL);

  EmitWarningsOnPlaceholders("pgauditlogtofile");

  /* background worker */
  worker.bgw_flags = BGWORKER_SHMEM_ACCESS;
  worker.bgw_start_time = BgWorkerStart_RecoveryFinished;
  worker.bgw_restart_time = 1;
  worker.bgw_main_arg = Int32GetDatum(0);
  worker.bgw_notify_pid = 0;
  sprintf(worker.bgw_library_name, "pgauditlogtofile");
  sprintf(worker.bgw_function_name, "PgAuditLogToFileMain");
  snprintf(worker.bgw_name, BGW_MAXLEN, "pgauditlogtofile launcher");

  RegisterBackgroundWorker(&worker);

/* backend hooks */
#if (PG_VERSION_NUM >= 150000)
  prev_shmem_request_hook = shmem_request_hook;
  shmem_request_hook = PgAuditLogToFile_shmem_request;
#else
  RequestAddinShmemSpace(MAXALIGN(sizeof(PgAuditLogToFileShm)));
  RequestNamedLWLockTranche("pgauditlogtofile", 1);
#endif

  prev_shmem_startup_hook = shmem_startup_hook;
  shmem_startup_hook = PgAuditLogToFile_shmem_startup;
  prev_emit_log_hook = emit_log_hook;
  emit_log_hook = PgAuditLogToFile_emit_log;
}

/**
 * @brief Extension finalization
 * @param void
 * @return void
*/
void _PG_fini(void)
{
  emit_log_hook = prev_emit_log_hook;
  shmem_startup_hook = prev_shmem_startup_hook;
}
