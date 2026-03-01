#include "logtofile_execution_time.h"
#include "logtofile_vars.h"

/**
 * @brief ExecutorStart hook to record the start time of a statement.
 * @param queryDesc
 * @param eflags
 */
void PgAuditLogToFile_ExecutorStart_Time(QueryDesc *queryDesc, int eflags)
{
  INSTR_TIME_SET_CURRENT(pgaudit_ltf_statement_start_time);
}

/**
 * @brief ExecutorEnd hook to calculate and log the statement execution time.
 * @param queryDesc
 */
void PgAuditLogToFile_ExecutorEnd_Time(QueryDesc *queryDesc)
{
  INSTR_TIME_SET_CURRENT(pgaudit_ltf_statement_end_time);
}
