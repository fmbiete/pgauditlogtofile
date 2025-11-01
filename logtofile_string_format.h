/*-------------------------------------------------------------------------
 *
 * logtofile_string_format.h
 *      Functions to format data as strings
 *
 * Copyright (c) 2020-2025, Francisco Miguel Biete Banon
 *
 * This code is released under the PostgreSQL licence, as given at
 *  http://www.postgresql.org/about/licence/
 *-------------------------------------------------------------------------
 */
#ifndef _LOGTOFILE_STRING_FORMAT_H_
#define _LOGTOFILE_STRING_FORMAT_H_

#include <postgres.h>

extern char *PgAuditLogToFile_format_now_timestamp_millis(void);

#endif
