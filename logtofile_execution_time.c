/*-------------------------------------------------------------------------
 *
 * logtofile_execution_time.c
 *      Partial hooks to measure execution time
 *
 * Copyright (c) 2026, Francisco Miguel Biete Banon
 *
 * This code is released under the PostgreSQL licence, as given at
 *  http://www.postgresql.org/about/licence/
 *-------------------------------------------------------------------------
 */
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
  INSTR_TIME_SET_ZERO(pgaudit_ltf_statement_end_time);
}

/**
 * @brief ExecutorEnd hook to calculate and log the statement execution time.
 * @param queryDesc
 */
void PgAuditLogToFile_ExecutorEnd_Time(QueryDesc *queryDesc)
{
  INSTR_TIME_SET_CURRENT(pgaudit_ltf_statement_end_time);
}
