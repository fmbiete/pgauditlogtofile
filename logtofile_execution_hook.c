#include "logtofile_execution_hook.h"

#include "logtofile_execution_memory.h"
#include "logtofile_execution_time.h"
#include "logtofile_vars.h"

#include <executor/executor.h>

void PgAuditLogToFile_ExecutorStart_Hook(QueryDesc *queryDesc, int eflags)
{
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

void PgAuditLogToFile_ExecutorRun_Hook(QueryDesc *queryDesc, ScanDirection direction, uint64 count, bool execute_once)
{
  if (guc_pgaudit_ltf_log_execution_memory)
    PgAuditLogToFile_ExecutorRun_Memory(queryDesc, direction, count, execute_once);

  if (pgaudit_ltf_prev_ExecutorRun)
    pgaudit_ltf_prev_ExecutorRun(queryDesc, direction, count, execute_once);
  else
    standard_ExecutorRun(queryDesc, direction, count, execute_once);

  if (guc_pgaudit_ltf_log_execution_memory)
    PgAuditLogToFile_ExecutorRun_Memory(queryDesc, direction, count, execute_once);
}