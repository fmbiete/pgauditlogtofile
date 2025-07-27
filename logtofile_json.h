/*-------------------------------------------------------------------------
 *
 * logtofile_json.h
 *      Functions to create a json audit record
 *
 * Copyright (c) 2020-2025, Francisco Miguel Biete Banon
 *
 * This code is released under the PostgreSQL licence, as given at
 *  http://www.postgresql.org/about/licence/
 *-------------------------------------------------------------------------
 */
#ifndef _LOGTOFILE_JSON_H_
#define _LOGTOFILE_JSON_H_

#include <postgres.h>

/* Hook functions */
extern void PgAuditLogToFile_json_audit(StringInfo buf, const ErrorData *edata, int exclude_nchars);

#endif
