/*-------------------------------------------------------------------------
 *
 * logtofile_autoclose.h
 *      Autoclose thread for logtofile
 *
 * Copyright (c) 2020-2026, Francisco Miguel Biete Banon
 *
 * This code is released under the PostgreSQL licence, as given at
 *  http://www.postgresql.org/about/licence/
 *-------------------------------------------------------------------------
 */
#ifndef _LOGTOFILE_AUTOCLOSE_H_
#define _LOGTOFILE_AUTOCLOSE_H_

#include <postgres.h>

extern void *PgAuditLogToFile_autoclose_run(void *arg);

#endif
