/*-------------------------------------------------------------------------
 *
 * logtofile_execution_hook.h
 *      Functions to add Execution Hooks wrappers
 *
 * Copyright (c) 2026, Francisco Miguel Biete Banon
 *
 * This code is released under the PostgreSQL licence, as given at
 *  http://www.postgresql.org/about/licence/
 *-------------------------------------------------------------------------
 */
#ifndef _LOGTOFILE_EXECUTION_HOOK_H_
#define _LOGTOFILE_EXECUTION_HOOK_H_

#include <postgres.h>
#include <executor/executor.h>

extern void PgAuditLogToFile_ExecutorStart_Hook(QueryDesc *queryDesc, int eflags);
extern void PgAuditLogToFile_ExecutorEnd_Hook(QueryDesc *queryDesc);
extern void PgAuditLogToFile_ExecutorRun_Hook(QueryDesc *queryDesc, ScanDirection direction, uint64 count, bool execute_once);

#endif
