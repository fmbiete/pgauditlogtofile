/*-------------------------------------------------------------------------
 *
 * logtofile_errordata.h
 *      Functions to work with ErrorData struct
 *
 * Copyright (c) 2026, Francisco Miguel Biete Banon
 *
 * This code is released under the PostgreSQL licence, as given at
 *  http://www.postgresql.org/about/licence/
 *-------------------------------------------------------------------------
 */
#ifndef _LOGTOFILE_ERRORDATA_H_
#define _LOGTOFILE_ERRORDATA_H_

#include <postgres.h>
#include <utils/elog.h>

extern void PgAuditLogToFile_CopyPendingErrorData(ErrorData *edata);
extern void PgAuditLogToFile_FreePendingErrorData(void);

#endif