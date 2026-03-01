#include "logtofile_execution.h"
#include "logtofile_vars.h"

#include <executor/executor.h>

/**
 * @brief ExecutorStart hook to record the start time of a statement.
 * @param queryDesc
 * @param eflags
 */
void PgAuditLogToFile_ExecutorStart(QueryDesc *queryDesc, int eflags)
{
  if (guc_pgaudit_ltf_log_execution_time)
  {
    pgaudit_ltf_statement_start_time = GetCurrentTimestamp();
  }

  if (pgaudit_ltf_prev_ExecutorStart)
    pgaudit_ltf_prev_ExecutorStart(queryDesc, eflags);
  else
    standard_ExecutorStart(queryDesc, eflags);
}

/**
 * @brief ExecutorEnd hook to calculate and log the statement execution time.
 * @param queryDesc
 */
void PgAuditLogToFile_ExecutorEnd(QueryDesc *queryDesc)
{
  pgaudit_ltf_statement_end_time = GetCurrentTimestamp();

  // int64 diff;
  // long secs;
  // int microsecs;
  // TimestampTz statement_end_time = GetCurrentTimestamp();

  // TimestampDifference(pgaudit_ltf_statement_start_time, statement_end_time, &secs, &microsecs);

  // ereport(LOG,
  //         (errmsg("Statement execution time: %ld.%06d seconds",
  //                 secs, microsecs)));

  if (pgaudit_ltf_prev_ExecutorEnd)
    pgaudit_ltf_prev_ExecutorEnd(queryDesc);
  else
    standard_ExecutorEnd(queryDesc);
}
