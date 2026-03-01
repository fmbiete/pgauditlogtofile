/*-------------------------------------------------------------------------
 *
 * logtofile_execution_time.h
 *      Partial hooks to measure execution time
 *
 * Copyright (c) 2026, Francisco Miguel Biete Banon
 *
 * This code is released under the PostgreSQL licence, as given at
 *  http://www.postgresql.org/about/licence/
 *-------------------------------------------------------------------------
 */
#ifndef _LOGTOFILE_EXECUTION_TIME_H_
#define _LOGTOFILE_EXECUTION_TIME_H_

#include <postgres.h>
#include <executor/executor.h>

extern void PgAuditLogToFile_ExecutorStart_Time(QueryDesc *queryDesc, int eflags);
extern void PgAuditLogToFile_ExecutorEnd_Time(QueryDesc *queryDesc);

#endif
