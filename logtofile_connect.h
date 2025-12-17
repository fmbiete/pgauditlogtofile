/*-------------------------------------------------------------------------
 *
 * logtofile_connect.h
 *      Functions to parse connect and disconnect messages
 *
 * Copyright (c) 2020-2026, Francisco Miguel Biete Banon
 *
 * This code is released under the PostgreSQL licence, as given at
 *  http://www.postgresql.org/about/licence/
 *-------------------------------------------------------------------------
 */
#ifndef _LOGTOFILE_CONNECT_H_
#define _LOGTOFILE_CONNECT_H_

#include <postgres.h>

extern char **
PgAuditLogToFile_connect_UniquePrefixes(const char **messages, const size_t num_messages, size_t *num_unique);

#endif
