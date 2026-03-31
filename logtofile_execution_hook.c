/*-------------------------------------------------------------------------
 *
 * logtofile_execution_hook.c
 *      Functions to add Execution Hooks wrappers
 *
 * Copyright (c) 2026, Francisco Miguel Biete Banon
 *
 * This code is released under the PostgreSQL licence, as given at
 *  http://www.postgresql.org/about/licence/
 *-------------------------------------------------------------------------
 */
#include "logtofile_execution_hook.h"

#include "logtofile_execution_memory.h"
#include "logtofile_execution_time.h"
#include "logtofile_vars.h"
#include "logtofile_signal_handler.h"
#include "logtofile_log.h"

#include <executor/executor.h>
#include <port.h>

static bool pgaudit_ltf_handler_setup = false;

/**
 * @brief Hook for ExecutorStart to setup signal handlers and stats capture
 * @param queryDesc query descriptor
 * @param eflags executor flags
 */
void PgAuditLogToFile_ExecutorStart_Hook(QueryDesc *queryDesc, int eflags)
{
  if (!pgaudit_ltf_handler_setup)
  {
#if (PG_VERSION_NUM >= 180000)
    /* setup a signal handler for SIGUSR1 in the backend, and hope we don't lose another */
    pqsignal(SIGUSR1, PgAuditLogToFile_SIGUSR1);
#else
    /* setup a signal handler for SIGUSR1 in the backend, and save the existing */
    pgaudit_ltf_prev_sigusr1_handler = pqsignal(SIGUSR1, PgAuditLogToFile_SIGUSR1);
#endif
    pgaudit_ltf_handler_setup = true; /* only once */
  }

  if (pgaudit_ltf_prev_ExecutorStart)
    pgaudit_ltf_prev_ExecutorStart(queryDesc, eflags);
  else
    standard_ExecutorStart(queryDesc, eflags);

  if (guc_pgaudit_ltf_log_execution_time)
    PgAuditLogToFile_ExecutorStart_Time(queryDesc, eflags);
  if (guc_pgaudit_ltf_log_execution_memory)
    PgAuditLogToFile_ExecutorStart_Memory(queryDesc, eflags);
}

/**
 * @brief Hook for ExecutorEnd to finalize stats and flush pending logs
 * @param queryDesc query descriptor
 */
void PgAuditLogToFile_ExecutorEnd_Hook(QueryDesc *queryDesc)
{
  if (guc_pgaudit_ltf_log_execution_time)
    PgAuditLogToFile_ExecutorEnd_Time(queryDesc);
  if (guc_pgaudit_ltf_log_execution_memory)
    PgAuditLogToFile_ExecutorEnd_Memory(queryDesc);

  /* Flush buffered audit records now that we have the stats */
  PgAuditLogToFile_Flush_Pending();

  /* Reset timing and memory variables to 0 so unrelated logs (like disconnection) don't use them */
  if (guc_pgaudit_ltf_log_execution_time)
  {
    INSTR_TIME_SET_ZERO(pgaudit_ltf_statement_start_time);
    INSTR_TIME_SET_ZERO(pgaudit_ltf_statement_end_time);
  }
  if (guc_pgaudit_ltf_log_execution_memory)
  {
    pgaudit_ltf_statement_memory_start = 0;
    pgaudit_ltf_statement_memory_end = 0;
    pgaudit_ltf_statement_memory_peak = 0;
  }

  if (pgaudit_ltf_prev_ExecutorEnd)
    pgaudit_ltf_prev_ExecutorEnd(queryDesc);
  else
    standard_ExecutorEnd(queryDesc);
}

#if (PG_VERSION_NUM >= 180000)
#define EX_RUN_ARGS queryDesc, direction, count
void PgAuditLogToFile_ExecutorRun_Hook(QueryDesc *queryDesc, ScanDirection direction, uint64 count)
#else
#define EX_RUN_ARGS queryDesc, direction, count, execute_once
/**
 * @brief Hook for ExecutorRun to track peak memory usage
 * @param queryDesc query descriptor
 * @param direction scan direction
 * @param count tuple count
 * @param execute_once execution flag
 */
void PgAuditLogToFile_ExecutorRun_Hook(QueryDesc *queryDesc, ScanDirection direction, uint64 count, bool execute_once)
#endif
{
  if (guc_pgaudit_ltf_log_execution_memory)
    PgAuditLogToFile_ExecutorRun_Memory(EX_RUN_ARGS);

  if (pgaudit_ltf_prev_ExecutorRun)
    pgaudit_ltf_prev_ExecutorRun(EX_RUN_ARGS);
  else
    standard_ExecutorRun(EX_RUN_ARGS);

  if (guc_pgaudit_ltf_log_execution_memory)
    PgAuditLogToFile_ExecutorRun_Memory(EX_RUN_ARGS);
}