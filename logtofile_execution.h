/*-------------------------------------------------------------------------
 *
 * logtofile_execution.h
 *      Functions to add Execution Hooks
 *
 * Copyright (c) 2026, Francisco Miguel Biete Banon
 *
 * This code is released under the PostgreSQL licence, as given at
 *  http://www.postgresql.org/about/licence/
 *-------------------------------------------------------------------------
 */
#ifndef _LOGTOFILE_EXECUTION_H_
#define _LOGTOFILE_EXECUTION_H_

#include <postgres.h>
#include <executor/executor.h>

extern void PgAuditLogToFile_ExecutorStart(QueryDesc *queryDesc, int eflags);
extern void PgAuditLogToFile_ExecutorEnd(QueryDesc *queryDesc);

#endif
