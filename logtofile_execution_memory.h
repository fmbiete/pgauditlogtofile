/*-------------------------------------------------------------------------
 *
 * logtofile_execution_memory.h
 *      Partial hooks to measure memory footprint of execution
 *
 * Copyright (c) 2026, Francisco Miguel Biete Banon
 *
 * This code is released under the PostgreSQL licence, as given at
 *  http://www.postgresql.org/about/licence/
 *-------------------------------------------------------------------------
 */
#ifndef _LOGTOFILE_EXECUTION_MEMORY_H_
#define _LOGTOFILE_EXECUTION_MEMORY_H_

#include <postgres.h>
#include <executor/executor.h>

extern void PgAuditLogToFile_ExecutorStart_Memory(QueryDesc *queryDesc, int eflags);
extern void PgAuditLogToFile_ExecutorEnd_Memory(QueryDesc *queryDesc);
#if (PG_VERSION_NUM >= 180000)
extern void PgAuditLogToFile_ExecutorRun_Memory(QueryDesc *queryDesc, ScanDirection direction, uint64 count);
#else
extern void PgAuditLogToFile_ExecutorRun_Memory(QueryDesc *queryDesc, ScanDirection direction, uint64 count, bool execute_once);
#endif

#endif
