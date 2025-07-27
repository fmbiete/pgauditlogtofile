/*-------------------------------------------------------------------------
 *
 * logtofile_log.h
 *      Functions to write audit logs to file
 *
 * Copyright (c) 2020-2025, Francisco Miguel Biete Banon
 *
 * This code is released under the PostgreSQL licence, as given at
 *  http://www.postgresql.org/about/licence/
 *-------------------------------------------------------------------------
 */
#ifndef _LOGTOFILE_LOG_H_
#define _LOGTOFILE_LOG_H_

#include <postgres.h>

/* Hook functions */
extern void PgAuditLogToFile_emit_log(ErrorData *edata);

#endif
