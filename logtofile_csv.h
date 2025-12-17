/*-------------------------------------------------------------------------
 *
 * logtofile_csv.h
 *      Functions to create a csv audit record
 *
 * Copyright (c) 2020-2026, Francisco Miguel Biete Banon
 *
 * This code is released under the PostgreSQL licence, as given at
 *  http://www.postgresql.org/about/licence/
 *-------------------------------------------------------------------------
 */
#ifndef _LOGTOFILE_CVS_H_
#define _LOGTOFILE_CVS_H_

#include <postgres.h>
#include <lib/stringinfo.h>

extern void PgAuditLogToFile_csv_audit(StringInfo buf, const ErrorData *edata, int exclude_nchars);

#endif
