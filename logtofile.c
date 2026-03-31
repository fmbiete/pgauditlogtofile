/*-------------------------------------------------------------------------
 *
 * logtofile.c
 *      Main entry point for logtofile
 *
 * Copyright (c) 2020-2026, Francisco Miguel Biete Banon
 *
 * This code is released under the PostgreSQL licence, as given at
 *  http://www.postgresql.org/about/licence/
 *-------------------------------------------------------------------------
 */
#include "logtofile.h"

#include "logtofile_bgw.h"
#include "logtofile_connect.h"
#include "logtofile_execution_hook.h"
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
#include <utils/memutils.h>
#include <datatype/timestamp.h>

static const struct config_enum_entry format_options[] = {
    {"csv", PGAUDIT_LTF_FORMAT_CSV, false},
    {"json", PGAUDIT_LTF_FORMAT_JSON, false},
    {NULL, 0, false}};

static const struct config_enum_entry compression_options[] = {
    {"off", PGAUDIT_LTF_COMPRESSION_OFF, false},
    {"gzip", PGAUDIT_LTF_COMPRESSION_GZIP, false},
    {"lz4", PGAUDIT_LTF_COMPRESSION_LZ4, false},
    {"zstd", PGAUDIT_LTF_COMPRESSION_ZSTD, false},
    {NULL, 0, false}};

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
    ereport(ERROR, (errmsg("pgauditlogtofile can only be loaded via shared_preload_libraries"),
                    errhint("Add pgauditlogtofile to the shared_preload_libraries configuration variable in postgresql.conf.")));
  }
  
  PG_TRY();
  {
    pgaudit_ltf_memory_context = AllocSetContextCreate(TopMemoryContext, "pgauditlogtofile context", ALLOCSET_DEFAULT_MINSIZE,
                                                          ALLOCSET_DEFAULT_INITSIZE, ALLOCSET_DEFAULT_MAXSIZE);
  }
  PG_CATCH();
  {
    FlushErrorState();
    ereport(FATAL, (errmsg("could not create pgauditlogtofile memory context")));
  }
  PG_END_TRY();

  /* guc variables */
  DefineCustomStringVariable(
      "pgaudit.log_directory",
      "Directory where to spool log data", NULL,
      &guc_pgaudit_ltf_log_directory,
      "log",
      PGC_SIGHUP, GUC_NOT_IN_SAMPLE | GUC_SUPERUSER_ONLY,
      PgAuditLogToFile_guc_check_directory, NULL, NULL);

  DefineCustomStringVariable(
      "pgaudit.log_filename",
      "Filename with time patterns (up to minutes) where to spool audit data", NULL,
      &guc_pgaudit_ltf_log_filename,
      "audit-%Y%m%d_%H%M.log",
      PGC_SIGHUP, GUC_NOT_IN_SAMPLE | GUC_SUPERUSER_ONLY,
      PgAuditLogToFile_guc_check_filename, NULL, NULL);

  DefineCustomIntVariable(
      "pgaudit.log_file_mode",
      "Sets the file permissions for log files", NULL,
      &guc_pgaudit_ltf_log_file_mode,
      0600, 0000, 0666,
      PGC_SIGHUP, GUC_NOT_IN_SAMPLE | GUC_SUPERUSER_ONLY,
      NULL, NULL, PgAuditLogToFile_guc_show_file_mode);

  DefineCustomIntVariable(
      "pgaudit.log_rotation_age",
      "Automatic spool file rotation will occur after N minutes", NULL,
      &guc_pgaudit_ltf_log_rotation_age,
      HOURS_PER_DAY * MINS_PER_HOUR, 0, INT_MAX / SECS_PER_MINUTE,
      PGC_SIGHUP, GUC_NOT_IN_SAMPLE | GUC_UNIT_MIN | GUC_SUPERUSER_ONLY,
      NULL, NULL, NULL);

  DefineCustomBoolVariable(
      "pgaudit.log_connections",
      "Intercepts log_connections messages", NULL,
      &guc_pgaudit_ltf_log_connections,
      false,
      PGC_SIGHUP, GUC_NOT_IN_SAMPLE | GUC_SUPERUSER_ONLY,
      NULL, NULL, NULL);

  DefineCustomBoolVariable(
      "pgaudit.log_disconnections",
      "Intercepts log_disconnections messages", NULL,
      &guc_pgaudit_ltf_log_disconnections,
      false,
      PGC_SIGHUP, GUC_NOT_IN_SAMPLE | GUC_SUPERUSER_ONLY,
      NULL, NULL, NULL);

  DefineCustomIntVariable(
      "pgaudit.log_autoclose_minutes",
      "Automatic spool file closure by backend after N minutes of inactivity", NULL,
      &guc_pgaudit_ltf_auto_close_minutes,
      0, 0, INT_MAX / MINS_PER_HOUR,
      PGC_SIGHUP,
      GUC_NOT_IN_SAMPLE | GUC_UNIT_MIN | GUC_SUPERUSER_ONLY, NULL, NULL, NULL);

  DefineCustomEnumVariable(
      "pgaudit.log_format",
      "Format of the audit data (csv or json)", NULL,
      &guc_pgaudit_ltf_log_format,
      PGAUDIT_LTF_FORMAT_CSV, format_options,
      PGC_SIGHUP, GUC_NOT_IN_SAMPLE | GUC_SUPERUSER_ONLY,
      NULL, NULL, NULL);

  DefineCustomBoolVariable(
      "pgaudit.log_execution_time",
      "Logs the execution time of each statement.", NULL,
      &guc_pgaudit_ltf_log_execution_time,
      false,
      PGC_POSTMASTER, GUC_NOT_IN_SAMPLE | GUC_SUPERUSER_ONLY,
      NULL, NULL, NULL);

  DefineCustomBoolVariable(
      "pgaudit.log_execution_memory",
      "Logs the memory usage of each statement.", NULL,
      &guc_pgaudit_ltf_log_execution_memory,
      false,
      PGC_POSTMASTER, GUC_NOT_IN_SAMPLE | GUC_SUPERUSER_ONLY,
      NULL, NULL, NULL);

  DefineCustomEnumVariable(
      "pgaudit.log_compression",
      "Compress the audit log file (off, gzip, lz4, zstd).", NULL,
      &guc_pgaudit_ltf_log_compression,
      PGAUDIT_LTF_COMPRESSION_OFF, compression_options,
      PGC_SIGHUP, GUC_NOT_IN_SAMPLE | GUC_SUPERUSER_ONLY,
      NULL, NULL, NULL);

  DefineCustomIntVariable(
      "pgaudit.log_compression_level",
      "Compression level (0=default, gzip: 1-9, lz4: 1-12, zstd: 1-22).", NULL,
      &guc_pgaudit_ltf_log_compression_level,
      0, 0, 22,
      PGC_SIGHUP, GUC_NOT_IN_SAMPLE | GUC_SUPERUSER_ONLY,
      NULL, NULL, NULL);

  EmitWarningsOnPlaceholders("pgauditlogtofile");

  /* background worker */
  MemSet(&worker, 0, sizeof(BackgroundWorker));
  worker.bgw_flags = BGWORKER_SHMEM_ACCESS;
  worker.bgw_start_time = BgWorkerStart_ConsistentState;
  worker.bgw_restart_time = 1;
  worker.bgw_main_arg = Int32GetDatum(0);
  worker.bgw_notify_pid = 0;
  sprintf(worker.bgw_library_name, "pgauditlogtofile");
  sprintf(worker.bgw_function_name, "PgAuditLogToFileMain");
  snprintf(worker.bgw_name, BGW_MAXLEN, "pgauditlogtofile launcher");

  RegisterBackgroundWorker(&worker);

  /* Executor hooks */
  pgaudit_ltf_prev_ExecutorStart = ExecutorStart_hook;
  ExecutorStart_hook = PgAuditLogToFile_ExecutorStart_Hook;
  pgaudit_ltf_prev_ExecutorEnd = ExecutorEnd_hook;
  ExecutorEnd_hook = PgAuditLogToFile_ExecutorEnd_Hook;
  pgaudit_ltf_prev_ExecutorRun = ExecutorRun_hook;
  ExecutorRun_hook = PgAuditLogToFile_ExecutorRun_Hook;

/* backend hooks */
#if (PG_VERSION_NUM >= 150000)
  pgaudit_ltf_prev_shmem_request_hook = shmem_request_hook;
  shmem_request_hook = PgAuditLogToFile_shmem_request;
#else
  PgAuditLogToFile_shmem_request();
#endif

  pgaudit_ltf_prev_shmem_startup_hook = shmem_startup_hook;
  shmem_startup_hook = PgAuditLogToFile_shmem_startup;
  pgaudit_ltf_prev_emit_log_hook = emit_log_hook;
  emit_log_hook = PgAuditLogToFile_emit_log;
}

/**
 * @brief Extension finalization
 * @param void
 * @return void
 */
void _PG_fini(void)
{
  emit_log_hook = pgaudit_ltf_prev_emit_log_hook;
  shmem_startup_hook = pgaudit_ltf_prev_shmem_startup_hook;

  ExecutorStart_hook = pgaudit_ltf_prev_ExecutorStart;
  ExecutorEnd_hook = pgaudit_ltf_prev_ExecutorEnd;

  if (pgaudit_ltf_memory_context != NULL)
  {
    MemoryContextDelete(pgaudit_ltf_memory_context);
    pgaudit_ltf_memory_context = NULL;
  }
}
