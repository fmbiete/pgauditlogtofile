#include "logtofile_execution_hook.h"

#include "logtofile_execution_memory.h"
#include "logtofile_execution_time.h"
#include "logtofile_vars.h"
#include "logtofile_signal_handler.h"
#include <libpq/pqsignal.h>

#include <executor/executor.h>

static bool pgaudit_ltf_handler_setup = false;

void PgAuditLogToFile_ExecutorStart_Hook(QueryDesc *queryDesc, int eflags)
{
  if (!pgaudit_ltf_handler_setup)
  {
    /* setup a signal handler for SIGUSR1 in the backend, and save the existing */
    pgaudit_ltf_prev_sigusr1_handler = pqsignal(SIGUSR1, PgAuditLogToFile_SIGUSR1);
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

void PgAuditLogToFile_ExecutorEnd_Hook(QueryDesc *queryDesc)
{
  if (guc_pgaudit_ltf_log_execution_time)
    PgAuditLogToFile_ExecutorEnd_Time(queryDesc);
  if (guc_pgaudit_ltf_log_execution_memory)
    PgAuditLogToFile_ExecutorEnd_Memory(queryDesc);

  if (pgaudit_ltf_prev_ExecutorEnd)
    pgaudit_ltf_prev_ExecutorEnd(queryDesc);
  else
    standard_ExecutorEnd(queryDesc);
}

#if (PG_VERSION_NUM >= 180000)
void PgAuditLogToFile_ExecutorRun_Hook(QueryDesc *queryDesc, ScanDirection direction, uint64 count)
#else
void PgAuditLogToFile_ExecutorRun_Hook(QueryDesc *queryDesc, ScanDirection direction, uint64 count, bool execute_once)
#endif
{
  if (guc_pgaudit_ltf_log_execution_memory)
  {
#if (PG_VERSION_NUM >= 180000)
    PgAuditLogToFile_ExecutorRun_Memory(queryDesc, direction, count);
#else
    PgAuditLogToFile_ExecutorRun_Memory(queryDesc, direction, count, execute_once);
#endif
  }

  if (pgaudit_ltf_prev_ExecutorRun)
  {
#if (PG_VERSION_NUM >= 180000)
    pgaudit_ltf_prev_ExecutorRun(queryDesc, direction, count);
#else
    pgaudit_ltf_prev_ExecutorRun(queryDesc, direction, count, execute_once);
#endif
  }
  else
  {
#if (PG_VERSION_NUM >= 180000)
    standard_ExecutorRun(queryDesc, direction, count);
#else
    standard_ExecutorRun(queryDesc, direction, count, execute_once);
#endif
  }

  if (guc_pgaudit_ltf_log_execution_memory)
  {
#if (PG_VERSION_NUM >= 180000)
    PgAuditLogToFile_ExecutorRun_Memory(queryDesc, direction, count);
#else
    PgAuditLogToFile_ExecutorRun_Memory(queryDesc, direction, count, execute_once);
#endif
  }
}