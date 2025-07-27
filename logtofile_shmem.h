/*-------------------------------------------------------------------------
 *
 * logtofile_shmem.h
 *      Functions to manage shared memory
 *
 * Copyright (c) 2020-2025, Francisco Miguel Biete Banon
 *
 * This code is released under the PostgreSQL licence, as given at
 *  http://www.postgresql.org/about/licence/
 *-------------------------------------------------------------------------
 */
#ifndef _LOGTOFILE_SHMEM_H_
#define _LOGTOFILE_SHMEM_H_

#include <postgres.h>

/* Hook functions */
extern void PgAuditLogToFile_shmem_startup(void);
extern void PgAuditLogToFile_shmem_shutdown(int code, Datum arg);
#if (PG_VERSION_NUM >= 150000)
extern void PgAuditLogToFile_shmem_request(void);
#endif

extern void PgAuditLogToFile_calculate_current_filename(void);
extern bool PgAuditLogToFile_needs_rotate_file(void);

#endif
