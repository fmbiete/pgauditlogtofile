/*-------------------------------------------------------------------------
 *
 * logtofile_bgw.h
 *      Background worker for logtofile
 *
 * Copyright (c) 2020-2024, Francisco Miguel Biete Banon
 *
 * This code is released under the PostgreSQL licence, as given at
 *  http://www.postgresql.org/about/licence/
 *-------------------------------------------------------------------------
 */
#ifndef _LOGTOFILE_BGW_H_
#define _LOGTOFILE_BGW_H_

#include <postgres.h>

extern PGDLLEXPORT void PgAuditLogToFileMain(Datum arg);

#endif
